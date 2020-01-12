use clap::{App, Arg};
use reqwest::Client;
use std::{path::Path, sync::Arc};

use iotedge_aad::{Auth, Context, Identity, Result};

// TODO add example from device ID creation to module access Azure resource

// iotedge-aad identity provision "module-a"
// iotedge-aad identity delete "module-a"
// iotedge-aad token "module-a"
#[tokio::main]
async fn main() -> Result<()> {
    let app = App::new("iotedge aad module identities integration")
        .subcommand(
            App::new("identity")
                .subcommand(App::new("list"))
                .subcommand(App::new("create").arg(Arg::with_name("module name").required(true)))
                .subcommand(App::new("delete").arg(Arg::with_name("module name").required(true))),
        )
        .subcommand(App::new("token").arg(Arg::with_name("module name").required(true)))
        //        .subcommand(App::new("storageaccount").short("sa").arg(Arg::with_name("module name").required(true)))
        .get_matches();

    let context = Context::from(Path::new("context.json"))?;

    let client = Arc::new(Client::new());
    let auth = Auth::authorize(client.clone(), context).await?;

    match app.subcommand() {
        ("identity", Some(matches)) => {
            let identity = Identity::new(client, auth);
            match matches.subcommand() {
                ("create", Some(args)) => {
                    let name = args.value_of("module name").unwrap();
                    println!("Creating module identity for module '{}'", name);

                    identity.provision(name).await
                }
                ("delete", Some(args)) => {
                    let name = args.value_of("module name").unwrap();
                    println!("Deleting module identity for module '{}'", name);

                    identity.delete(name).await
                }
                _ => unreachable!(),
            }
        }
        ("token", Some(args)) => {
            let name = args.value_of("module name").unwrap();
            println!("Obtaining auth token for module {}", name);
            unimplemented!()
        }
        _ => unreachable!(),
    }
}
