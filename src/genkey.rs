use crate::args::GenKeyArgs;

pub fn run(args: GenKeyArgs) {
    log::info!("Wants a key with {} bits", args.bits);
}
