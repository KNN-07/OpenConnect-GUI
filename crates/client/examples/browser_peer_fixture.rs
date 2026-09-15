//! Development-only hostile peer: never simulates successful browser authentication.
use ocvpn_model::{
    BrowserClientMessage as Incoming, BrowserHello, BrowserPage, BrowserPeerRole,
    BrowserServerMessage as Outgoing, Error, ErrorCode, SecretText,
    ipc::{read_frame, write_frame},
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--auth-window"] {
        return Err("Only the inherited browser fixture launch is supported".into());
    }
    let mode = std::env::var("OCVPN_BROWSER_ATTACK")?;
    let mut connection = ocvpn_client::browser_transport::connect().await?;
    write_frame(
        &mut connection.stream,
        &BrowserHello {
            version: 1,
            role: BrowserPeerRole::Embedded,
        },
    )
    .await?;
    let Outgoing::Open { request } = read_frame(&mut connection.stream).await? else {
        return Err("Browser request required".into());
    };
    write_frame(
        &mut connection.stream,
        &Incoming::Ready {
            transaction_id: request.transaction_id,
        },
    )
    .await?;
    match mode.as_str() {
        "wrong_origin" | "wrong_transaction" => {
            let transaction_id = if mode == "wrong_transaction" {
                Uuid::new_v4()
            } else {
                request.transaction_id
            };
            let uri = if mode == "wrong_origin" {
                "https://unrelated.invalid/".to_owned()
            } else {
                request.expected_origin.to_string()
            };
            let page = BrowserPage {
                uri: SecretText::new(uri),
                cookies: vec![],
                headers: vec![],
                document: None,
            };
            write_frame(
                &mut connection.stream,
                &Incoming::Page {
                    transaction_id,
                    page,
                },
            )
            .await?;
        }
        "secret_error" => {
            let error = Error {
                code: ErrorCode::RuntimeFailure,
                message: "fixture-secret-marker in callback URI".into(),
                details: Some("fixture-secret-marker in response".into()),
            };
            write_frame(
                &mut connection.stream,
                &Incoming::Failed {
                    transaction_id: request.transaction_id,
                    error,
                },
            )
            .await?;
        }
        "drop_mid_frame" => {
            connection.stream.write_u32(64).await?;
            connection.stream.write_all(b"{").await?;
            connection.stream.flush().await?;
            return Ok(());
        }
        "hold" => {}
        _ => return Err("Unknown adversarial fixture case".into()),
    }
    // Stay alive until cancellation/timeout closes the real broker transaction.
    loop {
        match read_frame::<_, Outgoing>(&mut connection.stream).await {
            Ok(Outgoing::Close { transaction_id }) if transaction_id == request.transaction_id => {
                return Ok(());
            }
            Err(_) => return Ok(()),
            _ => {}
        }
    }
}
