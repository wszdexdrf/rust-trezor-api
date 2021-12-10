use std::fmt;

use bitcoin::network::constants::Network; //TODO(stevenroose) change after https://github.com/rust-bitcoin/rust-bitcoin/pull/181
use bitcoin::util::bip32;
use bitcoin::util::psbt;
use bitcoin::Address;
use primitive_types::U256;
use secp256k1;
use unicode_normalization::UnicodeNormalization;

use super::Model;
use error::{Error, Result};
use flows::sign_tx::SignTxProgress;
use messages::TrezorMessage;
use protos;
use protos::MessageType::*;
use transport::{ProtoMessage, Transport};
use utils;

// Some types with raw protos that we use in the public interface so they have to be exported.
pub use protos::ButtonRequest_ButtonRequestType as ButtonRequestType;
pub use protos::Features;
pub use protos::InputScriptType;
pub use protos::PinMatrixRequest_PinMatrixRequestType as PinMatrixRequestType;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
/// An ECDSA signature
pub struct Signature {
	/// R value
	pub r: U256,
	/// S Value
	pub s: U256,
	/// V value in 'Electrum' notation.
	pub v: u64,
}

/// Access list item
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
	/// Accessed address
	pub address: String,
	/// Accessed storage keys
	pub storage_keys: Vec<Vec<u8>>,
}

/// The different options for the number of words in a seed phrase.
pub enum WordCount {
	W12 = 12,
	W18 = 18,
	W24 = 24,
}

/// The different types of user interactions the Trezor device can request.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum InteractionType {
	Button,
	PinMatrix,
	Passphrase,
	PassphraseState,
}

//TODO(stevenroose) should this be FnOnce and put in an FnBox?
/// Function to be passed to the `Trezor.call` method to process the Trezor response message into a
/// general-purpose type.
pub type ResultHandler<'a, T, R> = dyn Fn(&'a mut Trezor, R) -> Result<T>;

/// A button request message sent by the device.
pub struct ButtonRequest<'a, T, R: TrezorMessage> {
	message: protos::ButtonRequest,
	client: &'a mut Trezor,
	result_handler: Box<ResultHandler<'a, T, R>>,
}

impl<'a, T, R: TrezorMessage> fmt::Debug for ButtonRequest<'a, T, R> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(&self.message, f)
	}
}

impl<'a, T, R: TrezorMessage> ButtonRequest<'a, T, R> {
	/// The type of button request.
	pub fn request_type(&self) -> ButtonRequestType {
		self.message.get_code()
	}

	/// The metadata sent with the button request.
	// TODO now it returns pages
	// pub fn request_data(&self) -> &str {
	// 	self.message.get_data()
	// }

	/// Ack the request and get the next message from the device.
	pub fn ack(self) -> Result<TrezorResponse<'a, T, R>> {
		let req = protos::ButtonAck::new();
		self.client.call(req, self.result_handler)
	}
}

/// A PIN matrix request message sent by the device.
pub struct PinMatrixRequest<'a, T, R: TrezorMessage> {
	message: protos::PinMatrixRequest,
	client: &'a mut Trezor,
	result_handler: Box<ResultHandler<'a, T, R>>,
}

impl<'a, T, R: TrezorMessage> fmt::Debug for PinMatrixRequest<'a, T, R> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(&self.message, f)
	}
}

impl<'a, T, R: TrezorMessage> PinMatrixRequest<'a, T, R> {
	/// The type of PIN matrix request.
	pub fn request_type(&self) -> PinMatrixRequestType {
		self.message.get_field_type()
	}

	/// Ack the request with a PIN and get the next message from the device.
	pub fn ack_pin(self, pin: String) -> Result<TrezorResponse<'a, T, R>> {
		let mut req = protos::PinMatrixAck::new();
		req.set_pin(pin);
		self.client.call(req, self.result_handler)
	}
}

/// A passphrase request message sent by the device.
pub struct PassphraseRequest<'a, T, R: TrezorMessage> {
	message: protos::PassphraseRequest,
	client: &'a mut Trezor,
	result_handler: Box<ResultHandler<'a, T, R>>,
}

impl<'a, T, R: TrezorMessage> fmt::Debug for PassphraseRequest<'a, T, R> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(&self.message, f)
	}
}

impl<'a, T, R: TrezorMessage> PassphraseRequest<'a, T, R> {
	/// Check whether the use is supposed to enter the passphrase on the device or not.
	pub fn on_device(&self) -> bool {
		self.message.get__on_device()
	}

	/// Ack the request with a passphrase and get the next message from the device.
	pub fn ack_passphrase(self, passphrase: String) -> Result<TrezorResponse<'a, T, R>> {
		let mut req = protos::PassphraseAck::new();
		req.set_passphrase(passphrase);
		self.client.call(req, self.result_handler)
	}

	/// Ack the request without a passphrase to let the user enter it on the device
	/// and get the next message from the device.
	pub fn ack(self, on_device: bool) -> Result<TrezorResponse<'a, T, R>> {
		let mut req = protos::PassphraseAck::new();
		if on_device {
			req.set_on_device(on_device);
		}
		self.client.call(req, self.result_handler)
	}
}

/// A response from a Trezor device.  On every message exchange, instead of the expected/desired
/// response, the Trezor can ask for some user interaction, or can send a failure.
#[derive(Debug)]
pub enum TrezorResponse<'a, T, R: TrezorMessage> {
	Ok(T),
	Failure(protos::Failure),
	ButtonRequest(ButtonRequest<'a, T, R>),
	PinMatrixRequest(PinMatrixRequest<'a, T, R>),
	PassphraseRequest(PassphraseRequest<'a, T, R>),
	//TODO(stevenroose) This should be taken out of this enum and intrinsically attached to the
	// PassphraseRequest variant.  However, it's currently impossible to do this.  It might be
	// possible to do with FnBox (currently nightly) or when Box<FnOnce> becomes possible.
}

impl<'a, T, R: TrezorMessage> fmt::Display for TrezorResponse<'a, T, R> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			TrezorResponse::Ok(ref _m) => write!(f, "Ok"), //TODO(stevenroose) should we make T: Debug?
			TrezorResponse::Failure(ref m) => write!(f, "Failure: {:?}", m),
			TrezorResponse::ButtonRequest(ref r) => write!(f, "ButtonRequest: {:?}", r),
			TrezorResponse::PinMatrixRequest(ref r) => write!(f, "PinMatrixRequest: {:?}", r),
			TrezorResponse::PassphraseRequest(ref r) => write!(f, "PassphraseRequest: {:?}", r),
		}
	}
}

impl<'a, T, R: TrezorMessage> TrezorResponse<'a, T, R> {
	/// Get the actual `Ok` response value or an error if not `Ok`.
	pub fn ok(self) -> Result<T> {
		match self {
			TrezorResponse::Ok(m) => Ok(m),
			TrezorResponse::Failure(m) => Err(Error::FailureResponse(m)),
			TrezorResponse::ButtonRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Button))
			}
			TrezorResponse::PinMatrixRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::PinMatrix))
			}
			TrezorResponse::PassphraseRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Passphrase))
			}
		}
	}

	/// Get the button request object or an error if not `ButtonRequest`.
	pub fn button_request(self) -> Result<ButtonRequest<'a, T, R>> {
		match self {
			TrezorResponse::ButtonRequest(r) => Ok(r),
			TrezorResponse::Ok(_) => Err(Error::UnexpectedMessageType(R::message_type())),
			TrezorResponse::Failure(m) => Err(Error::FailureResponse(m)),
			TrezorResponse::PinMatrixRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::PinMatrix))
			}
			TrezorResponse::PassphraseRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Passphrase))
			}
		}
	}

	/// Get the PIN matrix request object or an error if not `PinMatrixRequest`.
	pub fn pin_matrix_request(self) -> Result<PinMatrixRequest<'a, T, R>> {
		match self {
			TrezorResponse::PinMatrixRequest(r) => Ok(r),
			TrezorResponse::Ok(_) => Err(Error::UnexpectedMessageType(R::message_type())),
			TrezorResponse::Failure(m) => Err(Error::FailureResponse(m)),
			TrezorResponse::ButtonRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Button))
			}
			TrezorResponse::PassphraseRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Passphrase))
			}
		}
	}

	/// Get the passphrase request object or an error if not `PassphraseRequest`.
	pub fn passphrase_request(self) -> Result<PassphraseRequest<'a, T, R>> {
		match self {
			TrezorResponse::PassphraseRequest(r) => Ok(r),
			TrezorResponse::Ok(_) => Err(Error::UnexpectedMessageType(R::message_type())),
			TrezorResponse::Failure(m) => Err(Error::FailureResponse(m)),
			TrezorResponse::ButtonRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::Button))
			}
			TrezorResponse::PinMatrixRequest(_) => {
				Err(Error::UnexpectedInteractionRequest(InteractionType::PinMatrix))
			}
		}
	}
}

fn handle_interaction<T, R: TrezorMessage>(resp: TrezorResponse<T, R>) -> Result<T> {
	match resp {
		TrezorResponse::Ok(res) => Ok(res),
		TrezorResponse::Failure(_) => resp.ok(), // assering ok() returns the failure error
		TrezorResponse::ButtonRequest(req) => handle_interaction(req.ack()?),
		TrezorResponse::PinMatrixRequest(_) => Err(Error::UnsupportedNetwork),
		TrezorResponse::PassphraseRequest(req) => handle_interaction({
			let on_device = req.on_device();
			req.ack(!on_device)?
		}),
	}
}

/// When resetting the device, it will ask for entropy to aid key generation.
pub struct EntropyRequest<'a> {
	client: &'a mut Trezor,
}

impl<'a> EntropyRequest<'a> {
	/// Provide exactly 32 bytes or entropy.
	pub fn ack_entropy(self, entropy: Vec<u8>) -> Result<TrezorResponse<'a, (), protos::Success>> {
		if entropy.len() != 32 {
			return Err(Error::InvalidEntropy);
		}

		let mut req = protos::EntropyAck::new();
		req.set_entropy(entropy);
		self.client.call(req, Box::new(|_, _| Ok(())))
	}
}

/// A Trezor client.
pub struct Trezor {
	model: Model,
	// Cached features for later inspection.
	features: Option<protos::Features>,
	transport: Box<dyn Transport>,
}

/// Create a new Trezor instance with the given transport.
pub fn trezor_with_transport(model: Model, transport: Box<dyn Transport>) -> Trezor {
	Trezor {
		model: model,
		transport: transport,
		features: None,
	}
}

impl Trezor {
	/// Get the model of the Trezor device.
	pub fn model(&self) -> Model {
		self.model
	}

	/// Get the features of the Trezor device.
	pub fn features(&self) -> Option<&protos::Features> {
		self.features.as_ref()
	}

	/// Sends a message and returns the raw ProtoMessage struct that was responded by the device.
	/// This method is only exported for users that want to expand the features of this library
	/// f.e. for supporting additional coins etc.
	pub fn call_raw<S: TrezorMessage>(&mut self, message: S) -> Result<ProtoMessage> {
		let proto_msg = ProtoMessage(S::message_type(), message.write_to_bytes()?);
		self.transport.write_message(proto_msg).map_err(|e| Error::TransportSendMessage(e))?;
		self.transport.read_message().map_err(|e| Error::TransportReceiveMessage(e))
	}

	/// Sends a message and returns a TrezorResponse with either the expected response message,
	/// a failure or an interaction request.
	/// This method is only exported for users that want to expand the features of this library
	/// f.e. for supporting additional coins etc.
	pub fn call<'a, T, S: TrezorMessage, R: TrezorMessage>(
		&'a mut self,
		message: S,
		result_handler: Box<ResultHandler<'a, T, R>>,
	) -> Result<TrezorResponse<'a, T, R>> {
		trace!("Sending {:?} msg: {:?}", S::message_type(), message);
		let resp = self.call_raw(message)?;
		if resp.message_type() == R::message_type() {
			let resp_msg = resp.into_message()?;
			trace!("Received {:?} msg: {:?}", R::message_type(), resp_msg);
			Ok(TrezorResponse::Ok(result_handler(self, resp_msg)?))
		} else {
			match resp.message_type() {
				MessageType_Failure => {
					let fail_msg = resp.into_message()?;
					debug!("Received failure: {:?}", fail_msg);
					Ok(TrezorResponse::Failure(fail_msg))
				}
				MessageType_ButtonRequest => {
					let req_msg = resp.into_message()?;
					trace!("Received ButtonRequest: {:?}", req_msg);
					Ok(TrezorResponse::ButtonRequest(ButtonRequest {
						message: req_msg,
						client: self,
						result_handler: result_handler,
					}))
				}
				MessageType_PinMatrixRequest => {
					let req_msg = resp.into_message()?;
					trace!("Received PinMatrixRequest: {:?}", req_msg);
					Ok(TrezorResponse::PinMatrixRequest(PinMatrixRequest {
						message: req_msg,
						client: self,
						result_handler: result_handler,
					}))
				}
				MessageType_PassphraseRequest => {
					let req_msg = resp.into_message()?;
					trace!("Received PassphraseRequest: {:?}", req_msg);
					Ok(TrezorResponse::PassphraseRequest(PassphraseRequest {
						message: req_msg,
						client: self,
						result_handler: result_handler,
					}))
				}
				mtype => {
					debug!(
						"Received unexpected msg type: {:?}; raw msg: {}",
						mtype,
						hex::encode(resp.into_payload())
					);
					Err(Error::UnexpectedMessageType(mtype))
				}
			}
		}
	}

	pub fn init_device(&mut self, session_id: Option<Vec<u8>>) -> Result<()> {
		let features = self.initialize(session_id)?.ok()?;
		self.features = Some(features);
		Ok(())
	}

	pub fn initialize(
		&mut self,
		session_id: Option<Vec<u8>>,
	) -> Result<TrezorResponse<Features, Features>> {
		let mut req = protos::Initialize::new();
		if let Some(session_id) = session_id {
			req.set_session_id(session_id);
		}
		self.call(req, Box::new(|_, m| Ok(m)))
	}

	pub fn ping(&mut self, message: &str) -> Result<TrezorResponse<(), protos::Success>> {
		let mut req = protos::Ping::new();
		req.set_message(message.to_owned());
		self.call(req, Box::new(|_, _| Ok(())))
	}

	pub fn change_pin(&mut self, remove: bool) -> Result<TrezorResponse<(), protos::Success>> {
		let mut req = protos::ChangePin::new();
		req.set_remove(remove);
		self.call(req, Box::new(|_, _| Ok(())))
	}

	pub fn wipe_device(&mut self) -> Result<TrezorResponse<(), protos::Success>> {
		let req = protos::WipeDevice::new();
		self.call(req, Box::new(|_, _| Ok(())))
	}

	pub fn recover_device(
		&mut self,
		word_count: WordCount,
		passphrase_protection: bool,
		pin_protection: bool,
		label: String,
		dry_run: bool,
	) -> Result<TrezorResponse<(), protos::Success>> {
		let mut req = protos::RecoveryDevice::new();
		req.set_word_count(word_count as u32);
		req.set_passphrase_protection(passphrase_protection);
		req.set_pin_protection(pin_protection);
		req.set_label(label);
		req.set_enforce_wordlist(true);
		req.set_dry_run(dry_run);
		req.set_field_type(
			protos::RecoveryDevice_RecoveryDeviceType::RecoveryDeviceType_ScrambledWords,
		);
		//TODO(stevenroose) support languages
		req.set_language("english".to_owned());
		self.call(req, Box::new(|_, _| Ok(())))
	}

	pub fn reset_device(
		&mut self,
		display_random: bool,
		strength: usize,
		passphrase_protection: bool,
		pin_protection: bool,
		label: String,
		skip_backup: bool,
		no_backup: bool,
	) -> Result<TrezorResponse<EntropyRequest, protos::EntropyRequest>> {
		let mut req = protos::ResetDevice::new();
		req.set_display_random(display_random);
		req.set_strength(strength as u32);
		req.set_passphrase_protection(passphrase_protection);
		req.set_pin_protection(pin_protection);
		req.set_label(label);
		req.set_skip_backup(skip_backup);
		req.set_no_backup(no_backup);
		self.call(
			req,
			Box::new(|c, _| {
				Ok(EntropyRequest {
					client: c,
				})
			}),
		)
	}

	pub fn backup(&mut self) -> Result<TrezorResponse<(), protos::Success>> {
		let req = protos::BackupDevice::new();
		self.call(req, Box::new(|_, _| Ok(())))
	}

	//TODO(stevenroose) support U2F stuff? currently ignored all

	pub fn apply_settings(
		&mut self,
		label: Option<String>,
		use_passphrase: Option<bool>,
		homescreen: Option<Vec<u8>>,
		auto_lock_delay_ms: Option<usize>,
	) -> Result<TrezorResponse<(), protos::Success>> {
		let mut req = protos::ApplySettings::new();
		if let Some(label) = label {
			req.set_label(label);
		}
		if let Some(use_passphrase) = use_passphrase {
			req.set_use_passphrase(use_passphrase);
		}
		if let Some(homescreen) = homescreen {
			req.set_homescreen(homescreen);
		}
		if let Some(auto_lock_delay_ms) = auto_lock_delay_ms {
			req.set_auto_lock_delay_ms(auto_lock_delay_ms as u32);
		}
		self.call(req, Box::new(|_, _| Ok(())))
	}

	pub fn get_public_key(
		&mut self,
		path: &bip32::DerivationPath,
		script_type: InputScriptType,
		network: Network,
		show_display: bool,
	) -> Result<TrezorResponse<bip32::ExtendedPubKey, protos::PublicKey>> {
		let mut req = protos::GetPublicKey::new();
		req.set_address_n(utils::convert_path(&path));
		req.set_show_display(show_display);
		req.set_coin_name(utils::coin_name(network)?);
		req.set_script_type(script_type);
		self.call(req, Box::new(|_, m| Ok(m.get_xpub().parse()?)))
	}

	//TODO(stevenroose) multisig
	pub fn get_address(
		&mut self,
		path: &bip32::DerivationPath,
		script_type: InputScriptType,
		network: Network,
		show_display: bool,
	) -> Result<TrezorResponse<Address, protos::Address>> {
		let mut req = protos::GetAddress::new();
		req.set_address_n(utils::convert_path(&path));
		req.set_coin_name(utils::coin_name(network)?);
		req.set_show_display(show_display);
		req.set_script_type(script_type);
		self.call(req, Box::new(|_, m| Ok(m.get_address().parse()?)))
	}

	pub fn sign_tx(
		&mut self,
		psbt: &psbt::PartiallySignedTransaction,
		network: Network,
	) -> Result<TrezorResponse<SignTxProgress, protos::TxRequest>> {
		let tx = &psbt.global.unsigned_tx;
		let mut req = protos::SignTx::new();
		req.set_inputs_count(tx.input.len() as u32);
		req.set_outputs_count(tx.output.len() as u32);
		req.set_coin_name(utils::coin_name(network)?);
		req.set_version(tx.version);
		req.set_lock_time(tx.lock_time);
		self.call(req, Box::new(|c, m| Ok(SignTxProgress::new(c, m))))
	}

	pub fn sign_message(
		&mut self,
		message: String,
		path: &bip32::DerivationPath,
		script_type: InputScriptType,
		network: Network,
	) -> Result<TrezorResponse<(Address, secp256k1::RecoverableSignature), protos::MessageSignature>>
	{
		let mut req = protos::SignMessage::new();
		req.set_address_n(utils::convert_path(&path));
		// Normalize to Unicode NFC.
		let msg_bytes = message.nfc().collect::<String>().into_bytes();
		req.set_message(msg_bytes);
		req.set_coin_name(utils::coin_name(network)?);
		req.set_script_type(script_type);
		self.call(
			req,
			Box::new(|_, m| {
				let address = m.get_address().parse()?;
				let signature = utils::parse_recoverable_signature(m.get_signature())?;
				Ok((address, signature))
			}),
		)
	}

	pub fn sign_identity(
		&mut self,
		identity: protos::IdentityType,
		digest: Vec<u8>,
		curve: String,
	) -> Result<TrezorResponse<Vec<u8>, protos::SignedIdentity>> {
		let mut req = protos::SignIdentity::new();
		req.set_identity(identity);
		req.set_challenge_hidden(digest);
		req.set_challenge_visual("".to_owned());
		req.set_ecdsa_curve_name(curve);
		self.call(req, Box::new(|_, m| Ok(m.get_signature().to_owned())))
	}

	// ETHEREUM
	pub fn ethereum_get_address(&mut self, path: Vec<u32>) -> Result<String> {
		let mut req = protos::EthereumGetAddress::new();
		req.set_address_n(path.clone());

		let address = handle_interaction(
			self.call(req, Box::new(|_, m: protos::EthereumAddress| Ok(m.get_address().into())))?,
		)?;
		Ok(address)
	}

	pub fn ethereum_sign_message(&mut self, message: Vec<u8>, path: Vec<u32>) -> Result<Signature> {
		let mut req = protos::EthereumSignMessage::new();
		req.set_address_n(path);
		req.set_message(message);
		let signature = handle_interaction(self.call(
			req,
			Box::new(|_, m: protos::EthereumMessageSignature| {
				let signature = m.get_signature();

				// why are you in the end
				let v = signature[64] as u64;
				let r = U256::from_big_endian(&signature[0..32]);
				let s = U256::from_big_endian(&signature[32..64]);

				Ok(Signature {
					r,
					v,
					s,
				})
			}),
		)?)?;

		Ok(signature)
	}

	pub fn ethereum_sign_tx(
		&mut self,
		path: Vec<u32>,
		nonce: Vec<u8>,
		gas_price: Vec<u8>,
		gas_limit: Vec<u8>,
		to: String,
		value: Vec<u8>,
		_data: Vec<u8>,
		chain_id: u64,
	) -> Result<Signature> {
		let mut req = protos::EthereumSignTx::new();
		let mut data = _data.clone();

		req.set_address_n(path);
		req.set_nonce(nonce);
		req.set_gas_price(gas_price);
		req.set_gas_limit(gas_limit);
		req.set_value(value);
		req.set_chain_id(chain_id);
		req.set_to(to);

		req.set_data_length(data.len() as u32);
		req.set_data_initial_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

		let mut resp =
			handle_interaction(self.call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?)?;

		while resp.get_data_length() > 0 {
			let mut ack = protos::EthereumTxAck::new();
			ack.set_data_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

			resp = self.call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?.ok()?;
		}

		if resp.get_signature_v() <= 1 {
			resp.set_signature_v(resp.get_signature_v() + 2 * (chain_id as u32) + 35);
		}

		Ok(Signature {
			r: resp.get_signature_r().into(),
			v: resp.get_signature_v().into(),
			s: resp.get_signature_s().into(),
		})
	}

	pub fn ethereum_sign_eip1559_tx(
		&mut self,
		path: Vec<u32>,
		nonce: Vec<u8>,
		gas_limit: Vec<u8>,
		to: String,
		value: Vec<u8>,
		_data: Vec<u8>,
		chain_id: u64,
		max_gas_fee: Vec<u8>,
		max_priority_fee: Vec<u8>,
		access_list: Vec<AccessListItem>,
	) -> Result<Signature> {
		let mut req = protos::EthereumSignTxEIP1559::new();
		let mut data = _data.clone();

		req.set_address_n(path);
		req.set_nonce(nonce);
		req.set_max_gas_fee(max_gas_fee);
		req.set_max_priority_fee(max_priority_fee);
		req.set_gas_limit(gas_limit);
		req.set_value(value);
		req.set_chain_id(chain_id);
		req.set_to(to);

		if access_list.len() > 0 {
			let mut list_access = Vec::new();

			for item in access_list {
				let mut access = protos::EthereumSignTxEIP1559_EthereumAccessList::new();

				access.set_address(item.address);
				access.set_storage_keys(protobuf::RepeatedField::from_vec(item.storage_keys));

				list_access.push(access)
			}

			req.set_access_list(protobuf::RepeatedField::from_vec(list_access.clone()));
		}

		req.set_data_length(data.len() as u32);
		req.set_data_initial_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

		let mut resp = handle_interaction(
			self.call(req, Box::new(|_, m: protos::EthereumTxRequest| Ok(m))).unwrap(),
		)?;

		while resp.get_data_length() > 0 {
			let mut ack = protos::EthereumTxAck::new();
			ack.set_data_chunk(data.splice(..std::cmp::min(1024, data.len()), []).collect());

			resp = self.call(ack, Box::new(|_, m: protos::EthereumTxRequest| Ok(m)))?.ok()?
		}

		if resp.get_signature_v() <= 1 {
			resp.set_signature_v(resp.get_signature_v() + 2 * (chain_id as u32) + 35);
		}

		Ok(Signature {
			r: resp.get_signature_r().into(),
			v: resp.get_signature_v().into(),
			s: resp.get_signature_s().into(),
		})
	}
}
