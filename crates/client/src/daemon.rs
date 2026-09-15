//! Shared authenticated daemon access. Cancelling a partial frame closes its stream.
use ocvpn_model::{
    Error, ErrorCode, Result, Snapshot,
    ipc::{self, Event, EventPayload, Hello, Method, Payload, Request, Response},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
trait ControlIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ControlIo for T {}
type Stream = Box<dyn ControlIo>;

fn unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "Tunnel service is unavailable. Install or repair the service, then retry; connection state is unknown.",
    )
}
fn transport_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        Error::new(
            ErrorCode::AuthorizationDenied,
            "The tunnel service endpoint could not be authenticated. Repair the installation; no credentials were sent.",
        )
    } else {
        unavailable()
    }
}
fn protocol_error() -> Error {
    Error::new(
        ErrorCode::ProtocolViolation,
        "The tunnel service returned an incompatible response. Repair or update the installation.",
    )
}

pub struct Connection {
    stream: Option<Stream>,
}
impl Connection {
    pub async fn open() -> Result<Self> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            #[cfg(unix)]
            let mut stream: Stream = Box::new(
                ocvpn_service::unix::connect_control()
                    .await
                    .map_err(transport_error)?,
            );
            #[cfg(windows)]
            let mut stream: Stream =
                Box::new(ocvpn_service::windows::connect_control().map_err(transport_error)?);
            ipc::write_frame(
                &mut stream,
                &Hello {
                    version: ipc::VERSION,
                },
            )
            .await?;
            ipc::read_frame::<_, Hello>(&mut stream).await?.validate()?;
            Ok(Self {
                stream: Some(stream),
            })
        })
        .await
        .map_err(|_| unavailable())?
    }

    /// One request at a time. Cancellation invalidates this connection and closes
    /// a held authentication reservation instead of retaining a partial frame.
    pub async fn call(&mut self, method: Method) -> Result<Payload> {
        let mut stream = self.stream.take().ok_or_else(unavailable)?;
        let request_id = Uuid::new_v4();
        let response: Response = tokio::time::timeout(REQUEST_TIMEOUT, async {
            ipc::write_frame(&mut stream, &Request { request_id, method }).await?;
            ipc::read_frame(&mut stream).await
        })
        .await
        .map_err(|_| unavailable())??;
        if response.request_id != request_id {
            return Err(protocol_error());
        }
        self.stream = Some(stream);
        response.result
    }

    pub async fn snapshot(&mut self) -> Result<Snapshot> {
        match self.call(Method::Snapshot).await? {
            Payload::Snapshot(snapshot) => Ok(snapshot),
            _ => Err(protocol_error()),
        }
    }

    pub async fn subscribe(mut self) -> Result<Events> {
        let Payload::Snapshot(snapshot) = self.call(Method::Subscribe).await? else {
            return Err(protocol_error());
        };
        let initial = Event {
            service_instance_id: snapshot.service_instance_id,
            sequence: snapshot.sequence,
            payload: EventPayload::Snapshot(snapshot),
        };
        Ok(Events {
            stream: self.stream.take(),
            last: None,
            initial: Some(initial),
            backlog: Vec::new(),
            log_stream: false,
        })
    }
    pub async fn follow_logs(mut self) -> Result<Events> {
        let Payload::Logs(backlog) = self.call(Method::Logs { follow: true }).await? else {
            return Err(protocol_error());
        };
        Ok(Events {
            stream: self.stream.take(),
            last: None,
            initial: None,
            backlog,
            log_stream: true,
        })
    }
}

pub struct Events {
    stream: Option<Stream>,
    last: Option<(Uuid, u64)>,
    initial: Option<Event>,
    backlog: Vec<ocvpn_model::LogRecord>,
    log_stream: bool,
}
impl Events {
    pub fn take_backlog(&mut self) -> Vec<ocvpn_model::LogRecord> {
        std::mem::take(&mut self.backlog)
    }
    /// Consume the globally sequenced wire stream, but expose only the requested
    /// event kind. Dropping an in-progress read requires a fresh subscription.
    pub async fn next(&mut self) -> Result<Event> {
        loop {
            let event = if let Some(initial) = self.initial.take() {
                initial
            } else {
                let mut stream = self.stream.take().ok_or_else(unavailable)?;
                let event: Event = ipc::read_frame(&mut stream).await?;
                self.stream = Some(stream);
                event
            };
            if event.service_instance_id.is_nil() {
                return Err(protocol_error());
            }
            if let EventPayload::Snapshot(snapshot) = &event.payload {
                if snapshot.service_instance_id != event.service_instance_id
                    || snapshot.sequence != event.sequence
                {
                    return Err(protocol_error());
                }
            }
            if let Some((instance, sequence)) = self.last {
                if instance == event.service_instance_id && event.sequence <= sequence {
                    continue;
                }
                if instance != event.service_instance_id
                    || sequence.checked_add(1) != Some(event.sequence)
                {
                    if self.log_stream {
                        return Err(Error::new(
                            ErrorCode::ServiceUnavailable,
                            "Log stream lost events; reconnect to reload recent records",
                        ));
                    }
                    let snapshot = Connection::open().await?.snapshot().await?;
                    self.last = Some((snapshot.service_instance_id, snapshot.sequence));
                    return Ok(Event {
                        service_instance_id: snapshot.service_instance_id,
                        sequence: snapshot.sequence,
                        payload: EventPayload::Snapshot(snapshot),
                    });
                }
            }
            self.last = Some((event.service_instance_id, event.sequence));
            if matches!(&event.payload, EventPayload::Log(_)) != self.log_stream {
                continue;
            }
            return Ok(event);
        }
    }
}

pub async fn snapshot() -> Result<Snapshot> {
    Connection::open().await?.snapshot().await
}
pub async fn disconnect() -> Result<()> {
    match Connection::open().await?.call(Method::Disconnect).await? {
        Payload::Accepted => Ok(()),
        _ => Err(protocol_error()),
    }
}
