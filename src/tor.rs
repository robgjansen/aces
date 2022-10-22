use std::{
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::Context;
use ctrlc;

use crate::args::{EncryptArgs, EncryptTorArgs};

pub fn run_encrypt_tor(_args: &EncryptArgs, tor_args: &EncryptTorArgs) -> anyhow::Result<()> {
    if tor_args.output.is_some() && tor_args.rotate.is_some() {
        anyhow::bail!(
            "You can't specify both an output path and file rotation. To use rotation, use the default auto-generated output path.",
        );
    }

    // Install signal handler to track that we received SIGINT.
    let got_sigint = set_sigint_handler()?;

    let (producers, receiver) = {
        let events = tor_args.event.join(" ");
        let (sender, receiver) = mpsc::channel();
        let producers = tor_args
            .socket
            .iter()
            .map(|path| {
                spawn_a_producer(
                    path.clone(),
                    events.clone(),
                    sender.clone(),
                    got_sigint.clone(),
                )
            })
            .collect::<Vec<_>>();
        (producers, receiver)
    };

    let runtime = match tor_args.rotate {
        Some(rotate_interval) => rotate_interval.into(),
        None => Duration::from_secs(3600 * 24 * 365 * 10),
    };

    loop {
        // TODO make a new encryptor/encoder chain here
        // and pass it as the Write output for the consumer

        if let Err(e) = run_consumer(&receiver, &mut std::io::stdout(), runtime, &got_sigint) {
            log::error!("Encountered IO error running consumer: {}", e);
            break;
        }
    }

    // Cleanup. Drop the receiver to close the channel and stop the producers.
    drop(receiver);
    for handle in producers {
        if let Err(_) = handle.join() {
            log::error!("Encountered error joining producer thread");
        }
    }

    Ok(())
}

fn set_sigint_handler() -> anyhow::Result<Arc<AtomicBool>> {
    let got_sigint = Arc::new(AtomicBool::new(false));
    let is_ctrlc = got_sigint.clone();

    ctrlc::set_handler(move || {
        if is_ctrlc.load(Ordering::Relaxed) {
            // User is persistent, wants to close NOW
            log::info!("Received SIGINT. Exiting NOW...");
            std::process::exit(1);
        } else {
            log::info!("Received SIGINT. Shutting down gracefully...");
            is_ctrlc.store(true, Ordering::Relaxed);
        }
    })
    .context("Error setting ctrl-c handler")?;

    Ok(got_sigint)
}

fn run_consumer<W: Write>(
    receiver: &Receiver<String>,
    output: &mut W,
    runtime: Duration,
    got_sigint: &Arc<AtomicBool>,
) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(runtime)
        .expect("Runtime should not overflow Instant");

    loop {
        let now = Instant::now();
        let timeout = deadline.saturating_duration_since(now);

        if timeout.is_zero() {
            return Ok(());
        }

        if got_sigint.load(Ordering::Relaxed) {
            return Ok(());
        }

        // Consume next line from channel
        match receiver.recv_timeout(timeout) {
            Ok(line) => output.write_all(line.as_ref())?,
            Err(e) => match e {
                RecvTimeoutError::Disconnected => {
                    log::warn!("Channel is disconnected for receiver.");
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                RecvTimeoutError::Timeout => return Ok(()),
            },
        }
    }
}

/// Spawns a producer thread in a new func so the spawned thread has no access
/// to borrowed references.
fn spawn_a_producer(
    socket_path: PathBuf,
    events: String,
    sender: Sender<String>,
    got_sigint: Arc<AtomicBool>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || run_producer(socket_path, events, sender, got_sigint))
}

/// A Tor control client that connects to a Tor control UNIX socket file,
/// receives Tor control events, and sends them using the given sender channel.
fn run_producer(
    socket_file: PathBuf,
    events: String,
    sender: Sender<String>,
    got_sigint: Arc<AtomicBool>,
) -> io::Result<()> {
    let mut stream = UnixStream::connect(socket_file)?;

    let cmds = std::format!("AUTHENTICATE\nSETEVENTS {}\n", events);
    stream.write_all(cmds.as_bytes())?;

    const READ_BUF_SIZE: usize = 2usize.pow(15u32); // 32 KiB
    let mut reader = BufReader::with_capacity(READ_BUF_SIZE, &stream);

    loop {
        if got_sigint.load(Ordering::Relaxed) {
            return Ok(());
        }

        let mut line = String::new();

        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            // EOF
            return Ok(());
        }

        if line.starts_with("650 ") {
            if let Err(_) = sender.send(line) {
                // Channel disconnected, so we're done
                return Ok(());
            }
        }
    }
}
