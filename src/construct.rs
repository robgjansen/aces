use crate::args::ConstructArgs;

pub fn run(args: ConstructArgs) {
    log::info!("Wants to construct files using key at path {:?}", args.key);
}
