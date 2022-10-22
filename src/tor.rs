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
    time::Instant,
};

use anyhow::Context;
use ctrlc;
use zstd::stream::write::Encoder;

use crate::{
    args::{EncryptArgs, EncryptTorArgs},
    crypto::AutoEncryptor,
    util,
};

pub fn run_encrypt_tor(args: &EncryptArgs, tor_args: &EncryptTorArgs) -> anyhow::Result<()> {
    if tor_args.output.is_some() && tor_args.rotate.is_some() {
        anyhow::bail!(
            "You can't specify both an output path and file rotation. To use rotation, use the default auto-generated output path.",
        );
    }

    // Install signal handler to track when we receiv SIGINT.
    let got_sigint = set_sigint_handler()?;

    // Start the IO threads to get lines from Tor and pass into channel.
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

    // Loop once for every rotation interval.
    loop {
        if got_sigint.load(Ordering::Relaxed) {
            log::info!("Breaking consumer loop.");
            break;
        }

        if let Err(e) = run_encrypt_chain(args, tor_args, &receiver, &got_sigint) {
            log::error!("Encountered IO error running consumer: {}", e);
            break;
        }
    }

    // Cleanup. Drop the receiver to close the channel and stop the producers.
    log::info!("Dropping receiver channel.");
    drop(receiver);

    log::info!("Joining producer threads.");
    for handle in producers {
        if let Err(_) = handle.join() {
            log::error!("Encountered error joining producer thread");
        }
    }

    Ok(())
}

fn run_encrypt_chain(
    args: &EncryptArgs,
    tor_args: &EncryptTorArgs,
    receiver: &Receiver<String>,
    got_sigint: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let output = match &tor_args.output {
        Some(path) => util::get_data_sink(path)?,
        None => util::get_data_sink(&util::gen_encrypt_outpath(
            &PathBuf::from("-"), // filename will be generated
            args.compress.unwrap(),
        )?)?,
    };

    let stop_at = tor_args
        .rotate
        .and_then(|rotate| Instant::now().checked_add(rotate.into()));

    let pub_key = util::get_pub_key(&args.key)?;

    let mut encryptor = AutoEncryptor::new(pub_key, output);

    let num_copied = if args.compress.unwrap() {
        log::info!("Tor-->Compressing-->Encrypting data stream...");

        let mut encoder =
            Encoder::new(encryptor, 0).context("Failure initializing zstd encoder")?;

        let num_copied = run_consumer(&receiver, &mut encoder, &stop_at, &got_sigint)
            .context("Failure running encoder-->encryptor chain")?;

        encryptor = encoder.finish().context("Failure finishing encoder")?;

        num_copied
    } else {
        log::info!("Tor-->Encrypting data stream...");
        run_consumer(&receiver, &mut encryptor, &stop_at, &got_sigint)
            .context("Failure running encryptor")?
    };

    encryptor.finish().context("Failure finishing encryptor")?;

    log::info!("Success! Processed {} bytes from input stream.", num_copied);
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
    stop_at: &Option<Instant>,
    got_sigint: &Arc<AtomicBool>,
) -> io::Result<usize> {
    let mut total_bytes: usize = 0;

    loop {
        if got_sigint.load(Ordering::Relaxed) {
            log::info!("Consumer interrupted.");
            return Ok(total_bytes);
        }

        // Consume next line from channel.
        let line = match stop_at {
            Some(deadline) => {
                // Block with a timeout so we can rotate file.
                let timeout = deadline.saturating_duration_since(Instant::now());

                if timeout.is_zero() {
                    log::info!("Consumer rotation timeout occurred.");
                    return Ok(total_bytes);
                }

                match receiver.recv_timeout(timeout) {
                    Ok(line) => line,
                    Err(e) => match e {
                        RecvTimeoutError::Disconnected => {
                            log::warn!("Channel is disconnected for receiver.");
                            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                        }
                        RecvTimeoutError::Timeout => {
                            log::info!("Consumer rotation timeout occurred.");
                            return Ok(total_bytes);
                        }
                    },
                }
            }
            None => {
                // Block indefinitely until we have input.
                match receiver.recv() {
                    Ok(line) => line,
                    Err(_) => {
                        log::warn!("Channel is disconnected for receiver.");
                        return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                    }
                }
            }
        };

        output.write_all(line.as_ref())?;
        total_bytes += line.len();
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
            log::info!("Producer {:?} interrupted.", thread::current().id());
            return Ok(());
        }

        let mut line = String::new();

        let bytes_read = match reader.read_line(&mut line) {
            Ok(count) => count,
            Err(e) => {
                log::info!(
                    "Producer {:?} received IO error {}.",
                    thread::current().id(),
                    e
                );
                return Err(e);
            }
        };

        if bytes_read == 0 {
            log::info!("Producer {:?} received EOF.", thread::current().id());
            return Ok(());
        }

        if line.starts_with("650 ") {
            if let Err(_) = sender.send(line) {
                log::info!(
                    "Producer {:?} channel was disconnected.",
                    thread::current().id()
                );
                return Ok(());
            }
        }
    }
}
