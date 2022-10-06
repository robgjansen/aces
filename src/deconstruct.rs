use crate::args::DeconstructArgs;

pub fn run(args: DeconstructArgs) {
    log::info!(
        "Wants to deconstruct files using key at path {:?}",
        args.key
    );
}
