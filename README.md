
# Rust Trezor API

A fork of a [fork](https://github.com/romanz/rust-trezor-api) of a [lib](https://github.com/stevenroose/rust-trezor-api), which provides a way to communicate with a Trezor T device from a rust project.

Previous iterations were focused on bitcoin-only, **this one focuses on providing an ethereum interface**, which can be used by [ethers-rs](https://github.com/gakonst/ethers-rs/).


## Requirements
Make sure you have trezor [udev](https://wiki.trezor.io/Udev_rules) rules installed: 

Tested with Firmware v2.4.2

## Examples / Tests
`cargo run --example features`

[`ethers-rs/blob/feature/trezor/ethers-signers/src/trezor/app.rs`](https://github.com/joshieDo/ethers-rs/blob/feature/trezor/ethers-signers/src/trezor/app.rs)

## Future
At the moment, not looking into expanding more than what's necessary to maintain compatability/usability with ethers-rs.

## Credits
* [TREZOR](https://github.com/trezor/trezor-firmware) 
* [stevenroose](https://github.com/stevenroose)
* [romanz](https://github.com/romanz)
