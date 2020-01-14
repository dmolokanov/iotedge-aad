use clap::{App, Arg};
use reqwest::Client;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use iotedge_aad::{Auth, Context, Identity, Result, TokenSource};

// TODO add example from device ID creation to module access Azure resource
#[tokio::main]
async fn main() -> Result<()> {
    let app = App::new("iotedge aad module identities integration")
        .arg(
            Arg::with_name("context")
                .long("context")
                .short("c")
                .default_value("context.json"),
        )
        .subcommand(
            App::new("identity")
                .long_about("Manages module identities")
                .subcommand(
                    App::new("provision")
                        .long_about("Provisions module identity")
                        .arg(Arg::with_name("module name").required(true))
                        .arg(Arg::with_name("cert").long("cert").takes_value(true)),
                )
                .subcommand(
                    App::new("delete")
                        .long_about("Deletes module identity")
                        .arg(Arg::with_name("module name").required(true)),
                ),
        )
        .subcommand(
            App::new("token")
                .long_about("Obtains module access token")
                .arg(Arg::with_name("module name").required(true))
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    let context = app.value_of("context").unwrap();
    let context = Context::from(Path::new(context))?;

    let client = Arc::new(Client::new());

    match app.subcommand() {
        ("identity", Some(matches)) => {
            let auth = Auth::graph(client.clone());
            let auth = auth
                .authorize_with_certificate(
                    context.tenant_id(),
                    context.client_id(),
                    PathBuf::from(context.cert()).as_path(),
                )
                .await?;

            let identity = Identity::new(client, auth);

            match matches.subcommand() {
                ("provision", Some(args)) => {
                    let name = args.value_of("module name").unwrap();
                    let cert_path = args.value_of("cert").map(PathBuf::from);
                    // println!("Creating module identity for module '{}'", name);

                    let created = identity.provision(name, cert_path).await?;
                    println!("{}", created.app_id);
                    // println!("Created new identity: {}", created.app_id);
                }
                ("delete", Some(args)) => {
                    let name = args.value_of("module name").unwrap();
                    println!("Deleting module identity for module '{}'", name);

                    identity.delete(name).await?;
                }
                _ => unreachable!(),
            }
        }
        ("token", Some(args)) => {
            let name = args.value_of("module name").unwrap();
            let client_id = args.value_of("id").expect("module app_id");
            let auth = Auth::azure(client);
            let auth = auth
                .authorize_with_certificate(
                    context.tenant_id(),
                    client_id,
                    PathBuf::from(format!("{}/cert.pem", name)).as_path(),
                )
                .await?;
            println!("{}", auth.get());
        }
        _ => unreachable!(),
    }
    Ok(())
}
