use crate::block::Block;


pub trait FeistelNetwork {
    #[allow(unused_variables)]
    fn run(&self, block: &mut Block<u32>) {
        return;
    }

    fn with_reversal(&self) -> impl FeistelNetwork;
}