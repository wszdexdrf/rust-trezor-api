use protobuf::Message;

use protos::{self, MessageType};

pub enum ProtoMessage {
	Initialize(protos::Initialize),
	Ping(protos::Ping),
	Success(protos::Success),
	Failure(protos::Failure),
	ChangePin(protos::ChangePin),
	WipeDevice(protos::WipeDevice),
	GetEntropy(protos::GetEntropy),
	Entropy(protos::Entropy),
	LoadDevice(protos::LoadDevice),
	ResetDevice(protos::ResetDevice),
	Features(protos::Features),
	PinMatrixRequest(protos::PinMatrixRequest),
	PinMatrixAck(protos::PinMatrixAck),
	Cancel(protos::Cancel),
	ClearSession(protos::ClearSession),
	ApplySettings(protos::ApplySettings),
	ButtonRequest(protos::ButtonRequest),
	ButtonAck(protos::ButtonAck),
	ApplyFlags(protos::ApplyFlags),
	BackupDevice(protos::BackupDevice),
	EntropyRequest(protos::EntropyRequest),
	EntropyAck(protos::EntropyAck),
	PassphraseRequest(protos::PassphraseRequest),
	PassphraseAck(protos::PassphraseAck),
	PassphraseStateRequest(protos::PassphraseStateRequest),
	PassphraseStateAck(protos::PassphraseStateAck),
	RecoveryDevice(protos::RecoveryDevice),
	WordRequest(protos::WordRequest),
	WordAck(protos::WordAck),
	GetFeatures(protos::GetFeatures),
	//SetU(protos::SetU),
	FirmwareErase(protos::FirmwareErase),
	FirmwareUpload(protos::FirmwareUpload),
	FirmwareRequest(protos::FirmwareRequest),
	SelfTest(protos::SelfTest),
	GetPublicKey(protos::GetPublicKey),
	PublicKey(protos::PublicKey),
	SignTx(protos::SignTx),
	TxRequest(protos::TxRequest),
	TxAck(protos::TxAck),
	GetAddress(protos::GetAddress),
	Address(protos::Address),
	SignMessage(protos::SignMessage),
	VerifyMessage(protos::VerifyMessage),
	MessageSignature(protos::MessageSignature),
	CipherKeyValue(protos::CipherKeyValue),
	CipheredKeyValue(protos::CipheredKeyValue),
	SignIdentity(protos::SignIdentity),
	SignedIdentity(protos::SignedIdentity),
	GetECDHSessionKey(protos::GetECDHSessionKey),
	ECDHSessionKey(protos::ECDHSessionKey),
	CosiCommit(protos::CosiCommit),
	CosiCommitment(protos::CosiCommitment),
	CosiSign(protos::CosiSign),
	CosiSignature(protos::CosiSignature),
	DebugLinkDecision(protos::DebugLinkDecision),
	DebugLinkGetState(protos::DebugLinkGetState),
	DebugLinkState(protos::DebugLinkState),
	DebugLinkStop(protos::DebugLinkStop),
	DebugLinkLog(protos::DebugLinkLog),
	DebugLinkMemoryRead(protos::DebugLinkMemoryRead),
	DebugLinkMemory(protos::DebugLinkMemory),
	DebugLinkMemoryWrite(protos::DebugLinkMemoryWrite),
	DebugLinkFlashErase(protos::DebugLinkFlashErase),
	EthereumGetAddress(protos::EthereumGetAddress),
	EthereumAddress(protos::EthereumAddress),
	EthereumSignTx(protos::EthereumSignTx),
	EthereumTxRequest(protos::EthereumTxRequest),
	EthereumTxAck(protos::EthereumTxAck),
	EthereumSignMessage(protos::EthereumSignMessage),
	EthereumVerifyMessage(protos::EthereumVerifyMessage),
	EthereumMessageSignature(protos::EthereumMessageSignature),
	NEMGetAddress(protos::NEMGetAddress),
	NEMAddress(protos::NEMAddress),
	NEMSignTx(protos::NEMSignTx),
	NEMSignedTx(protos::NEMSignedTx),
	NEMDecryptMessage(protos::NEMDecryptMessage),
	NEMDecryptedMessage(protos::NEMDecryptedMessage),
	LiskGetAddress(protos::LiskGetAddress),
	LiskAddress(protos::LiskAddress),
	LiskSignTx(protos::LiskSignTx),
	LiskSignedTx(protos::LiskSignedTx),
	LiskSignMessage(protos::LiskSignMessage),
	LiskMessageSignature(protos::LiskMessageSignature),
	LiskVerifyMessage(protos::LiskVerifyMessage),
	LiskGetPublicKey(protos::LiskGetPublicKey),
	LiskPublicKey(protos::LiskPublicKey),
	TezosGetAddress(protos::TezosGetAddress),
	TezosAddress(protos::TezosAddress),
	TezosSignTx(protos::TezosSignTx),
	TezosSignedTx(protos::TezosSignedTx),
	TezosGetPublicKey(protos::TezosGetPublicKey),
	TezosPublicKey(protos::TezosPublicKey),
	StellarSignTx(protos::StellarSignTx),
	StellarTxOpRequest(protos::StellarTxOpRequest),
	StellarGetAddress(protos::StellarGetAddress),
	StellarAddress(protos::StellarAddress),
	StellarCreateAccountOp(protos::StellarCreateAccountOp),
	StellarPaymentOp(protos::StellarPaymentOp),
	StellarPathPaymentOp(protos::StellarPathPaymentOp),
	StellarManageOfferOp(protos::StellarManageOfferOp),
	StellarCreatePassiveOfferOp(protos::StellarCreatePassiveOfferOp),
	StellarSetOptionsOp(protos::StellarSetOptionsOp),
	StellarChangeTrustOp(protos::StellarChangeTrustOp),
	StellarAllowTrustOp(protos::StellarAllowTrustOp),
	StellarAccountMergeOp(protos::StellarAccountMergeOp),
	StellarManageDataOp(protos::StellarManageDataOp),
	StellarBumpSequenceOp(protos::StellarBumpSequenceOp),
	StellarSignedTx(protos::StellarSignedTx),
	TronGetAddress(protos::TronGetAddress),
	TronAddress(protos::TronAddress),
	TronSignTx(protos::TronSignTx),
	TronSignedTx(protos::TronSignedTx),
	CardanoSignTx(protos::CardanoSignTx),
	CardanoTxRequest(protos::CardanoTxRequest),
	CardanoGetPublicKey(protos::CardanoGetPublicKey),
	CardanoPublicKey(protos::CardanoPublicKey),
	CardanoGetAddress(protos::CardanoGetAddress),
	CardanoAddress(protos::CardanoAddress),
	CardanoTxAck(protos::CardanoTxAck),
	CardanoSignedTx(protos::CardanoSignedTx),
	OntologyGetAddress(protos::OntologyGetAddress),
	OntologyAddress(protos::OntologyAddress),
	OntologyGetPublicKey(protos::OntologyGetPublicKey),
	OntologyPublicKey(protos::OntologyPublicKey),
	OntologySignTransfer(protos::OntologySignTransfer),
	OntologySignedTransfer(protos::OntologySignedTransfer),
	OntologySignWithdrawOng(protos::OntologySignWithdrawOng),
	OntologySignedWithdrawOng(protos::OntologySignedWithdrawOng),
	OntologySignOntIdRegister(protos::OntologySignOntIdRegister),
	OntologySignedOntIdRegister(protos::OntologySignedOntIdRegister),
	OntologySignOntIdAddAttributes(protos::OntologySignOntIdAddAttributes),
	OntologySignedOntIdAddAttributes(protos::OntologySignedOntIdAddAttributes),
	RippleGetAddress(protos::RippleGetAddress),
	RippleAddress(protos::RippleAddress),
	RippleSignTx(protos::RippleSignTx),
	RippleSignedTx(protos::RippleSignedTx),
	MoneroTransactionInitRequest(protos::MoneroTransactionInitRequest),
	MoneroTransactionInitAck(protos::MoneroTransactionInitAck),
	MoneroTransactionSetInputRequest(protos::MoneroTransactionSetInputRequest),
	MoneroTransactionSetInputAck(protos::MoneroTransactionSetInputAck),
	MoneroTransactionInputsPermutationRequest(protos::MoneroTransactionInputsPermutationRequest),
	MoneroTransactionInputsPermutationAck(protos::MoneroTransactionInputsPermutationAck),
	MoneroTransactionInputViniRequest(protos::MoneroTransactionInputViniRequest),
	MoneroTransactionInputViniAck(protos::MoneroTransactionInputViniAck),
	MoneroTransactionAllInputsSetRequest(protos::MoneroTransactionAllInputsSetRequest),
	MoneroTransactionAllInputsSetAck(protos::MoneroTransactionAllInputsSetAck),
	MoneroTransactionSetOutputRequest(protos::MoneroTransactionSetOutputRequest),
	MoneroTransactionSetOutputAck(protos::MoneroTransactionSetOutputAck),
	MoneroTransactionAllOutSetRequest(protos::MoneroTransactionAllOutSetRequest),
	MoneroTransactionAllOutSetAck(protos::MoneroTransactionAllOutSetAck),
	MoneroTransactionMlsagDoneRequest(protos::MoneroTransactionMlsagDoneRequest),
	MoneroTransactionMlsagDoneAck(protos::MoneroTransactionMlsagDoneAck),
	MoneroTransactionSignInputRequest(protos::MoneroTransactionSignInputRequest),
	MoneroTransactionSignInputAck(protos::MoneroTransactionSignInputAck),
	MoneroTransactionFinalRequest(protos::MoneroTransactionFinalRequest),
	MoneroTransactionFinalAck(protos::MoneroTransactionFinalAck),
	MoneroKeyImageExportInitRequest(protos::MoneroKeyImageExportInitRequest),
	MoneroKeyImageExportInitAck(protos::MoneroKeyImageExportInitAck),
	MoneroKeyImageSyncStepRequest(protos::MoneroKeyImageSyncStepRequest),
	MoneroKeyImageSyncStepAck(protos::MoneroKeyImageSyncStepAck),
	MoneroKeyImageSyncFinalRequest(protos::MoneroKeyImageSyncFinalRequest),
	MoneroKeyImageSyncFinalAck(protos::MoneroKeyImageSyncFinalAck),
	MoneroGetAddress(protos::MoneroGetAddress),
	MoneroAddress(protos::MoneroAddress),
	MoneroGetWatchKey(protos::MoneroGetWatchKey),
	MoneroWatchKey(protos::MoneroWatchKey),
	DebugMoneroDiagRequest(protos::DebugMoneroDiagRequest),
	DebugMoneroDiagAck(protos::DebugMoneroDiagAck),
}

impl ProtoMessage {
	pub fn message_type(&self) -> protos::MessageType {
		use self::ProtoMessage::*;
		use protos::MessageType::*;
		match self {
			Initialize(_) => MessageType_Initialize,
			Ping(_) => MessageType_Ping,
			Success(_) => MessageType_Success,
			Failure(_) => MessageType_Failure,
			ChangePin(_) => MessageType_ChangePin,
			WipeDevice(_) => MessageType_WipeDevice,
			GetEntropy(_) => MessageType_GetEntropy,
			Entropy(_) => MessageType_Entropy,
			LoadDevice(_) => MessageType_LoadDevice,
			ResetDevice(_) => MessageType_ResetDevice,
			Features(_) => MessageType_Features,
			PinMatrixRequest(_) => MessageType_PinMatrixRequest,
			PinMatrixAck(_) => MessageType_PinMatrixAck,
			Cancel(_) => MessageType_Cancel,
			ClearSession(_) => MessageType_ClearSession,
			ApplySettings(_) => MessageType_ApplySettings,
			ButtonRequest(_) => MessageType_ButtonRequest,
			ButtonAck(_) => MessageType_ButtonAck,
			ApplyFlags(_) => MessageType_ApplyFlags,
			BackupDevice(_) => MessageType_BackupDevice,
			EntropyRequest(_) => MessageType_EntropyRequest,
			EntropyAck(_) => MessageType_EntropyAck,
			PassphraseRequest(_) => MessageType_PassphraseRequest,
			PassphraseAck(_) => MessageType_PassphraseAck,
			PassphraseStateRequest(_) => MessageType_PassphraseStateRequest,
			PassphraseStateAck(_) => MessageType_PassphraseStateAck,
			RecoveryDevice(_) => MessageType_RecoveryDevice,
			WordRequest(_) => MessageType_WordRequest,
			WordAck(_) => MessageType_WordAck,
			GetFeatures(_) => MessageType_GetFeatures,
			//SetU(_) => MessageType_SetU,
			FirmwareErase(_) => MessageType_FirmwareErase,
			FirmwareUpload(_) => MessageType_FirmwareUpload,
			FirmwareRequest(_) => MessageType_FirmwareRequest,
			SelfTest(_) => MessageType_SelfTest,
			GetPublicKey(_) => MessageType_GetPublicKey,
			PublicKey(_) => MessageType_PublicKey,
			SignTx(_) => MessageType_SignTx,
			TxRequest(_) => MessageType_TxRequest,
			TxAck(_) => MessageType_TxAck,
			GetAddress(_) => MessageType_GetAddress,
			Address(_) => MessageType_Address,
			SignMessage(_) => MessageType_SignMessage,
			VerifyMessage(_) => MessageType_VerifyMessage,
			MessageSignature(_) => MessageType_MessageSignature,
			CipherKeyValue(_) => MessageType_CipherKeyValue,
			CipheredKeyValue(_) => MessageType_CipheredKeyValue,
			SignIdentity(_) => MessageType_SignIdentity,
			SignedIdentity(_) => MessageType_SignedIdentity,
			GetECDHSessionKey(_) => MessageType_GetECDHSessionKey,
			ECDHSessionKey(_) => MessageType_ECDHSessionKey,
			CosiCommit(_) => MessageType_CosiCommit,
			CosiCommitment(_) => MessageType_CosiCommitment,
			CosiSign(_) => MessageType_CosiSign,
			CosiSignature(_) => MessageType_CosiSignature,
			DebugLinkDecision(_) => MessageType_DebugLinkDecision,
			DebugLinkGetState(_) => MessageType_DebugLinkGetState,
			DebugLinkState(_) => MessageType_DebugLinkState,
			DebugLinkStop(_) => MessageType_DebugLinkStop,
			DebugLinkLog(_) => MessageType_DebugLinkLog,
			DebugLinkMemoryRead(_) => MessageType_DebugLinkMemoryRead,
			DebugLinkMemory(_) => MessageType_DebugLinkMemory,
			DebugLinkMemoryWrite(_) => MessageType_DebugLinkMemoryWrite,
			DebugLinkFlashErase(_) => MessageType_DebugLinkFlashErase,
			EthereumGetAddress(_) => MessageType_EthereumGetAddress,
			EthereumAddress(_) => MessageType_EthereumAddress,
			EthereumSignTx(_) => MessageType_EthereumSignTx,
			EthereumTxRequest(_) => MessageType_EthereumTxRequest,
			EthereumTxAck(_) => MessageType_EthereumTxAck,
			EthereumSignMessage(_) => MessageType_EthereumSignMessage,
			EthereumVerifyMessage(_) => MessageType_EthereumVerifyMessage,
			EthereumMessageSignature(_) => MessageType_EthereumMessageSignature,
			NEMGetAddress(_) => MessageType_NEMGetAddress,
			NEMAddress(_) => MessageType_NEMAddress,
			NEMSignTx(_) => MessageType_NEMSignTx,
			NEMSignedTx(_) => MessageType_NEMSignedTx,
			NEMDecryptMessage(_) => MessageType_NEMDecryptMessage,
			NEMDecryptedMessage(_) => MessageType_NEMDecryptedMessage,
			LiskGetAddress(_) => MessageType_LiskGetAddress,
			LiskAddress(_) => MessageType_LiskAddress,
			LiskSignTx(_) => MessageType_LiskSignTx,
			LiskSignedTx(_) => MessageType_LiskSignedTx,
			LiskSignMessage(_) => MessageType_LiskSignMessage,
			LiskMessageSignature(_) => MessageType_LiskMessageSignature,
			LiskVerifyMessage(_) => MessageType_LiskVerifyMessage,
			LiskGetPublicKey(_) => MessageType_LiskGetPublicKey,
			LiskPublicKey(_) => MessageType_LiskPublicKey,
			TezosGetAddress(_) => MessageType_TezosGetAddress,
			TezosAddress(_) => MessageType_TezosAddress,
			TezosSignTx(_) => MessageType_TezosSignTx,
			TezosSignedTx(_) => MessageType_TezosSignedTx,
			TezosGetPublicKey(_) => MessageType_TezosGetPublicKey,
			TezosPublicKey(_) => MessageType_TezosPublicKey,
			StellarSignTx(_) => MessageType_StellarSignTx,
			StellarTxOpRequest(_) => MessageType_StellarTxOpRequest,
			StellarGetAddress(_) => MessageType_StellarGetAddress,
			StellarAddress(_) => MessageType_StellarAddress,
			StellarCreateAccountOp(_) => MessageType_StellarCreateAccountOp,
			StellarPaymentOp(_) => MessageType_StellarPaymentOp,
			StellarPathPaymentOp(_) => MessageType_StellarPathPaymentOp,
			StellarManageOfferOp(_) => MessageType_StellarManageOfferOp,
			StellarCreatePassiveOfferOp(_) => MessageType_StellarCreatePassiveOfferOp,
			StellarSetOptionsOp(_) => MessageType_StellarSetOptionsOp,
			StellarChangeTrustOp(_) => MessageType_StellarChangeTrustOp,
			StellarAllowTrustOp(_) => MessageType_StellarAllowTrustOp,
			StellarAccountMergeOp(_) => MessageType_StellarAccountMergeOp,
			StellarManageDataOp(_) => MessageType_StellarManageDataOp,
			StellarBumpSequenceOp(_) => MessageType_StellarBumpSequenceOp,
			StellarSignedTx(_) => MessageType_StellarSignedTx,
			TronGetAddress(_) => MessageType_TronGetAddress,
			TronAddress(_) => MessageType_TronAddress,
			TronSignTx(_) => MessageType_TronSignTx,
			TronSignedTx(_) => MessageType_TronSignedTx,
			CardanoSignTx(_) => MessageType_CardanoSignTx,
			CardanoTxRequest(_) => MessageType_CardanoTxRequest,
			CardanoGetPublicKey(_) => MessageType_CardanoGetPublicKey,
			CardanoPublicKey(_) => MessageType_CardanoPublicKey,
			CardanoGetAddress(_) => MessageType_CardanoGetAddress,
			CardanoAddress(_) => MessageType_CardanoAddress,
			CardanoTxAck(_) => MessageType_CardanoTxAck,
			CardanoSignedTx(_) => MessageType_CardanoSignedTx,
			OntologyGetAddress(_) => MessageType_OntologyGetAddress,
			OntologyAddress(_) => MessageType_OntologyAddress,
			OntologyGetPublicKey(_) => MessageType_OntologyGetPublicKey,
			OntologyPublicKey(_) => MessageType_OntologyPublicKey,
			OntologySignTransfer(_) => MessageType_OntologySignTransfer,
			OntologySignedTransfer(_) => MessageType_OntologySignedTransfer,
			OntologySignWithdrawOng(_) => MessageType_OntologySignWithdrawOng,
			OntologySignedWithdrawOng(_) => MessageType_OntologySignedWithdrawOng,
			OntologySignOntIdRegister(_) => MessageType_OntologySignOntIdRegister,
			OntologySignedOntIdRegister(_) => MessageType_OntologySignedOntIdRegister,
			OntologySignOntIdAddAttributes(_) => MessageType_OntologySignOntIdAddAttributes,
			OntologySignedOntIdAddAttributes(_) => MessageType_OntologySignedOntIdAddAttributes,
			RippleGetAddress(_) => MessageType_RippleGetAddress,
			RippleAddress(_) => MessageType_RippleAddress,
			RippleSignTx(_) => MessageType_RippleSignTx,
			RippleSignedTx(_) => MessageType_RippleSignedTx,
			MoneroTransactionInitRequest(_) => MessageType_MoneroTransactionInitRequest,
			MoneroTransactionInitAck(_) => MessageType_MoneroTransactionInitAck,
			MoneroTransactionSetInputRequest(_) => MessageType_MoneroTransactionSetInputRequest,
			MoneroTransactionSetInputAck(_) => MessageType_MoneroTransactionSetInputAck,
			MoneroTransactionInputsPermutationRequest(_) => {
				MessageType_MoneroTransactionInputsPermutationRequest
			}
			MoneroTransactionInputsPermutationAck(_) => {
				MessageType_MoneroTransactionInputsPermutationAck
			}
			MoneroTransactionInputViniRequest(_) => MessageType_MoneroTransactionInputViniRequest,
			MoneroTransactionInputViniAck(_) => MessageType_MoneroTransactionInputViniAck,
			MoneroTransactionAllInputsSetRequest(_) => {
				MessageType_MoneroTransactionAllInputsSetRequest
			}
			MoneroTransactionAllInputsSetAck(_) => MessageType_MoneroTransactionAllInputsSetAck,
			MoneroTransactionSetOutputRequest(_) => MessageType_MoneroTransactionSetOutputRequest,
			MoneroTransactionSetOutputAck(_) => MessageType_MoneroTransactionSetOutputAck,
			MoneroTransactionAllOutSetRequest(_) => MessageType_MoneroTransactionAllOutSetRequest,
			MoneroTransactionAllOutSetAck(_) => MessageType_MoneroTransactionAllOutSetAck,
			MoneroTransactionMlsagDoneRequest(_) => MessageType_MoneroTransactionMlsagDoneRequest,
			MoneroTransactionMlsagDoneAck(_) => MessageType_MoneroTransactionMlsagDoneAck,
			MoneroTransactionSignInputRequest(_) => MessageType_MoneroTransactionSignInputRequest,
			MoneroTransactionSignInputAck(_) => MessageType_MoneroTransactionSignInputAck,
			MoneroTransactionFinalRequest(_) => MessageType_MoneroTransactionFinalRequest,
			MoneroTransactionFinalAck(_) => MessageType_MoneroTransactionFinalAck,
			MoneroKeyImageExportInitRequest(_) => MessageType_MoneroKeyImageExportInitRequest,
			MoneroKeyImageExportInitAck(_) => MessageType_MoneroKeyImageExportInitAck,
			MoneroKeyImageSyncStepRequest(_) => MessageType_MoneroKeyImageSyncStepRequest,
			MoneroKeyImageSyncStepAck(_) => MessageType_MoneroKeyImageSyncStepAck,
			MoneroKeyImageSyncFinalRequest(_) => MessageType_MoneroKeyImageSyncFinalRequest,
			MoneroKeyImageSyncFinalAck(_) => MessageType_MoneroKeyImageSyncFinalAck,
			MoneroGetAddress(_) => MessageType_MoneroGetAddress,
			MoneroAddress(_) => MessageType_MoneroAddress,
			MoneroGetWatchKey(_) => MessageType_MoneroGetWatchKey,
			MoneroWatchKey(_) => MessageType_MoneroWatchKey,
			DebugMoneroDiagRequest(_) => MessageType_DebugMoneroDiagRequest,
			DebugMoneroDiagAck(_) => MessageType_DebugMoneroDiagAck,
		}
	}

	fn to_bytes(&self) -> Vec<u8> {
		use self::ProtoMessage::*;
		match self {
			Initialize(ref m) => m.write_to_bytes(),
			Ping(ref m) => m.write_to_bytes(),
			Success(ref m) => m.write_to_bytes(),
			Failure(ref m) => m.write_to_bytes(),
			ChangePin(ref m) => m.write_to_bytes(),
			WipeDevice(ref m) => m.write_to_bytes(),
			GetEntropy(ref m) => m.write_to_bytes(),
			Entropy(ref m) => m.write_to_bytes(),
			LoadDevice(ref m) => m.write_to_bytes(),
			ResetDevice(ref m) => m.write_to_bytes(),
			Features(ref m) => m.write_to_bytes(),
			PinMatrixRequest(ref m) => m.write_to_bytes(),
			PinMatrixAck(ref m) => m.write_to_bytes(),
			Cancel(ref m) => m.write_to_bytes(),
			ClearSession(ref m) => m.write_to_bytes(),
			ApplySettings(ref m) => m.write_to_bytes(),
			ButtonRequest(ref m) => m.write_to_bytes(),
			ButtonAck(ref m) => m.write_to_bytes(),
			ApplyFlags(ref m) => m.write_to_bytes(),
			BackupDevice(ref m) => m.write_to_bytes(),
			EntropyRequest(ref m) => m.write_to_bytes(),
			EntropyAck(ref m) => m.write_to_bytes(),
			PassphraseRequest(ref m) => m.write_to_bytes(),
			PassphraseAck(ref m) => m.write_to_bytes(),
			PassphraseStateRequest(ref m) => m.write_to_bytes(),
			PassphraseStateAck(ref m) => m.write_to_bytes(),
			RecoveryDevice(ref m) => m.write_to_bytes(),
			WordRequest(ref m) => m.write_to_bytes(),
			WordAck(ref m) => m.write_to_bytes(),
			GetFeatures(ref m) => m.write_to_bytes(),
			//SetU(ref m) => m.write_to_bytes(),
			FirmwareErase(ref m) => m.write_to_bytes(),
			FirmwareUpload(ref m) => m.write_to_bytes(),
			FirmwareRequest(ref m) => m.write_to_bytes(),
			SelfTest(ref m) => m.write_to_bytes(),
			GetPublicKey(ref m) => m.write_to_bytes(),
			PublicKey(ref m) => m.write_to_bytes(),
			SignTx(ref m) => m.write_to_bytes(),
			TxRequest(ref m) => m.write_to_bytes(),
			TxAck(ref m) => m.write_to_bytes(),
			GetAddress(ref m) => m.write_to_bytes(),
			Address(ref m) => m.write_to_bytes(),
			SignMessage(ref m) => m.write_to_bytes(),
			VerifyMessage(ref m) => m.write_to_bytes(),
			MessageSignature(ref m) => m.write_to_bytes(),
			CipherKeyValue(ref m) => m.write_to_bytes(),
			CipheredKeyValue(ref m) => m.write_to_bytes(),
			SignIdentity(ref m) => m.write_to_bytes(),
			SignedIdentity(ref m) => m.write_to_bytes(),
			GetECDHSessionKey(ref m) => m.write_to_bytes(),
			ECDHSessionKey(ref m) => m.write_to_bytes(),
			CosiCommit(ref m) => m.write_to_bytes(),
			CosiCommitment(ref m) => m.write_to_bytes(),
			CosiSign(ref m) => m.write_to_bytes(),
			CosiSignature(ref m) => m.write_to_bytes(),
			DebugLinkDecision(ref m) => m.write_to_bytes(),
			DebugLinkGetState(ref m) => m.write_to_bytes(),
			DebugLinkState(ref m) => m.write_to_bytes(),
			DebugLinkStop(ref m) => m.write_to_bytes(),
			DebugLinkLog(ref m) => m.write_to_bytes(),
			DebugLinkMemoryRead(ref m) => m.write_to_bytes(),
			DebugLinkMemory(ref m) => m.write_to_bytes(),
			DebugLinkMemoryWrite(ref m) => m.write_to_bytes(),
			DebugLinkFlashErase(ref m) => m.write_to_bytes(),
			EthereumGetAddress(ref m) => m.write_to_bytes(),
			EthereumAddress(ref m) => m.write_to_bytes(),
			EthereumSignTx(ref m) => m.write_to_bytes(),
			EthereumTxRequest(ref m) => m.write_to_bytes(),
			EthereumTxAck(ref m) => m.write_to_bytes(),
			EthereumSignMessage(ref m) => m.write_to_bytes(),
			EthereumVerifyMessage(ref m) => m.write_to_bytes(),
			EthereumMessageSignature(ref m) => m.write_to_bytes(),
			NEMGetAddress(ref m) => m.write_to_bytes(),
			NEMAddress(ref m) => m.write_to_bytes(),
			NEMSignTx(ref m) => m.write_to_bytes(),
			NEMSignedTx(ref m) => m.write_to_bytes(),
			NEMDecryptMessage(ref m) => m.write_to_bytes(),
			NEMDecryptedMessage(ref m) => m.write_to_bytes(),
			LiskGetAddress(ref m) => m.write_to_bytes(),
			LiskAddress(ref m) => m.write_to_bytes(),
			LiskSignTx(ref m) => m.write_to_bytes(),
			LiskSignedTx(ref m) => m.write_to_bytes(),
			LiskSignMessage(ref m) => m.write_to_bytes(),
			LiskMessageSignature(ref m) => m.write_to_bytes(),
			LiskVerifyMessage(ref m) => m.write_to_bytes(),
			LiskGetPublicKey(ref m) => m.write_to_bytes(),
			LiskPublicKey(ref m) => m.write_to_bytes(),
			TezosGetAddress(ref m) => m.write_to_bytes(),
			TezosAddress(ref m) => m.write_to_bytes(),
			TezosSignTx(ref m) => m.write_to_bytes(),
			TezosSignedTx(ref m) => m.write_to_bytes(),
			TezosGetPublicKey(ref m) => m.write_to_bytes(),
			TezosPublicKey(ref m) => m.write_to_bytes(),
			StellarSignTx(ref m) => m.write_to_bytes(),
			StellarTxOpRequest(ref m) => m.write_to_bytes(),
			StellarGetAddress(ref m) => m.write_to_bytes(),
			StellarAddress(ref m) => m.write_to_bytes(),
			StellarCreateAccountOp(ref m) => m.write_to_bytes(),
			StellarPaymentOp(ref m) => m.write_to_bytes(),
			StellarPathPaymentOp(ref m) => m.write_to_bytes(),
			StellarManageOfferOp(ref m) => m.write_to_bytes(),
			StellarCreatePassiveOfferOp(ref m) => m.write_to_bytes(),
			StellarSetOptionsOp(ref m) => m.write_to_bytes(),
			StellarChangeTrustOp(ref m) => m.write_to_bytes(),
			StellarAllowTrustOp(ref m) => m.write_to_bytes(),
			StellarAccountMergeOp(ref m) => m.write_to_bytes(),
			StellarManageDataOp(ref m) => m.write_to_bytes(),
			StellarBumpSequenceOp(ref m) => m.write_to_bytes(),
			StellarSignedTx(ref m) => m.write_to_bytes(),
			TronGetAddress(ref m) => m.write_to_bytes(),
			TronAddress(ref m) => m.write_to_bytes(),
			TronSignTx(ref m) => m.write_to_bytes(),
			TronSignedTx(ref m) => m.write_to_bytes(),
			CardanoSignTx(ref m) => m.write_to_bytes(),
			CardanoTxRequest(ref m) => m.write_to_bytes(),
			CardanoGetPublicKey(ref m) => m.write_to_bytes(),
			CardanoPublicKey(ref m) => m.write_to_bytes(),
			CardanoGetAddress(ref m) => m.write_to_bytes(),
			CardanoAddress(ref m) => m.write_to_bytes(),
			CardanoTxAck(ref m) => m.write_to_bytes(),
			CardanoSignedTx(ref m) => m.write_to_bytes(),
			OntologyGetAddress(ref m) => m.write_to_bytes(),
			OntologyAddress(ref m) => m.write_to_bytes(),
			OntologyGetPublicKey(ref m) => m.write_to_bytes(),
			OntologyPublicKey(ref m) => m.write_to_bytes(),
			OntologySignTransfer(ref m) => m.write_to_bytes(),
			OntologySignedTransfer(ref m) => m.write_to_bytes(),
			OntologySignWithdrawOng(ref m) => m.write_to_bytes(),
			OntologySignedWithdrawOng(ref m) => m.write_to_bytes(),
			OntologySignOntIdRegister(ref m) => m.write_to_bytes(),
			OntologySignedOntIdRegister(ref m) => m.write_to_bytes(),
			OntologySignOntIdAddAttributes(ref m) => m.write_to_bytes(),
			OntologySignedOntIdAddAttributes(ref m) => m.write_to_bytes(),
			RippleGetAddress(ref m) => m.write_to_bytes(),
			RippleAddress(ref m) => m.write_to_bytes(),
			RippleSignTx(ref m) => m.write_to_bytes(),
			RippleSignedTx(ref m) => m.write_to_bytes(),
			MoneroTransactionInitRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionInitAck(ref m) => m.write_to_bytes(),
			MoneroTransactionSetInputRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionSetInputAck(ref m) => m.write_to_bytes(),
			MoneroTransactionInputsPermutationRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionInputsPermutationAck(ref m) => m.write_to_bytes(),
			MoneroTransactionInputViniRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionInputViniAck(ref m) => m.write_to_bytes(),
			MoneroTransactionAllInputsSetRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionAllInputsSetAck(ref m) => m.write_to_bytes(),
			MoneroTransactionSetOutputRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionSetOutputAck(ref m) => m.write_to_bytes(),
			MoneroTransactionAllOutSetRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionAllOutSetAck(ref m) => m.write_to_bytes(),
			MoneroTransactionMlsagDoneRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionMlsagDoneAck(ref m) => m.write_to_bytes(),
			MoneroTransactionSignInputRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionSignInputAck(ref m) => m.write_to_bytes(),
			MoneroTransactionFinalRequest(ref m) => m.write_to_bytes(),
			MoneroTransactionFinalAck(ref m) => m.write_to_bytes(),
			MoneroKeyImageExportInitRequest(ref m) => m.write_to_bytes(),
			MoneroKeyImageExportInitAck(ref m) => m.write_to_bytes(),
			MoneroKeyImageSyncStepRequest(ref m) => m.write_to_bytes(),
			MoneroKeyImageSyncStepAck(ref m) => m.write_to_bytes(),
			MoneroKeyImageSyncFinalRequest(ref m) => m.write_to_bytes(),
			MoneroKeyImageSyncFinalAck(ref m) => m.write_to_bytes(),
			MoneroGetAddress(ref m) => m.write_to_bytes(),
			MoneroAddress(ref m) => m.write_to_bytes(),
			MoneroGetWatchKey(ref m) => m.write_to_bytes(),
			MoneroWatchKey(ref m) => m.write_to_bytes(),
			DebugMoneroDiagRequest(ref m) => m.write_to_bytes(),
			DebugMoneroDiagAck(ref m) => m.write_to_bytes(),
		}
	}
}