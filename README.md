# aces:

asynchronously compress and encrypt streams (of data)

This utility will consume an input stream of data from stdin, a file, or a
running Tor process, compress-then-encrypt it, and write the encrypted blob to
the filesystem. It uses a public-key encryption scheme such that, when the
secret key is stored offline, the encrypted contents cannot be decrypted on the
machine that is producing the data stream.

`aces` is designed to be a useful utility in a network measurement pipeline.

### Build

Debug build (also used for tests):

    cargo build

Release build (optimized):

    cargo build --release

Run tests:

    cargo test

Run aces:

    cargo run -- -h
    ./target/{debug,release}/aces -h

### Usage

**Step 1: Generate a key-pair**

You should generate a public+secret key-pair offline, so that the secret key is
unavailable on the measurement machine (i.e., the machine producing the data
streams that you want to encrypt).

    aces gen-key --secret aces.sec.key --public aces.pub.key

Then copy `aces.pub.key` to the remote measurement machine.

**Step 2: Encrypt data**

Use `aces` on a remote measurement machine to encrypt data.

Encrypt data from `stdin`:

    aces encrypt aces.pub.key file -

Encrypt data from a file named `infile`:

    aces encrypt aces.pub.key file infile

Encrypt data from a file named `infile` with a custom output filename `outfile`:

    aces encrypt aces.pub.key file --output outfile infile

Use `-` as the file name to read/write to `stdin`/`stdout`:

    aces encrypt aces.pub.key file --output - -

Read from the control socket of a running Tor process, listening for any control event:

    aces encrypt aces.pub.key tor --event "BW,CIRC" path/to/control.sock 

Same, rotating the output file every day:

    aces encrypt aces.pub.key tor --event BW --event CIRC --rotate "1 day" path/to/control.sock 

**Step 3: Decrypt data**

Decrypt with the secret key, after copying the encrypted output files from the
measurement remote to your local machine.

    aces decrypt aces.sec.key --output outfile infile

Or using stdio:

    cat infile | aces decrypt aces.sec.key --output - - > outfile
