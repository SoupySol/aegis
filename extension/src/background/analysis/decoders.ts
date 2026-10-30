/**
 * decoders.ts
 * ---------------------------------------------------------------------------
 * PURPOSE:  Turns raw instructions (program id + account addresses + data)
 *           into plain-language DecodedInstructions for: System, SPL Token,
 *           Token-2022, Stake, Upgradeable Loader, Compute Budget, Associated
 *           Token Account and Memo. Anything else is shown as "Unknown".
 *
 * ACCESS:   Pure functions over instruction bytes.
 *
 * NEVER:    - No network. No storage. No logging.
 *           - A malformed instruction never throws out of this module; it is
 *             reported as "<Program>: Unparseable" instead.
 * ---------------------------------------------------------------------------
 */

import type { DecodedInstruction } from '../../shared/analysis-types';
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BPF_UPGRADEABLE_LOADER_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  MEMO_V1_PROGRAM_ID,
  STAKE_PROGRAM_ID,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  knownProgram,
} from '../../shared/known-programs';
import { ByteReader, formatSol } from './bytes';

/** Internal, richer form of DecodedInstruction used by the rules. */
export interface DecodedIx extends DecodedInstruction {
  /** Machine-readable type, e.g. "system:transfer", "token:setAuthority". "unknown" for unknown programs. */
  type: string;
  /** Resolved account addresses, in instruction order. */
  accounts: string[];
}

type Params = Record<string, string>;

const SYSTEM_NAMES = [
  'CreateAccount',
  'Assign',
  'Transfer',
  'CreateAccountWithSeed',
  'AdvanceNonceAccount',
  'WithdrawNonceAccount',
  'InitializeNonceAccount',
  'AuthorizeNonceAccount',
  'Allocate',
  'AllocateWithSeed',
  'AssignWithSeed',
  'TransferWithSeed',
  'UpgradeNonceAccount',
] as const;

const TOKEN_NAMES = [
  'InitializeMint',
  'InitializeAccount',
  'InitializeMultisig',
  'Transfer',
  'Approve',
  'Revoke',
  'SetAuthority',
  'MintTo',
  'Burn',
  'CloseAccount',
  'FreezeAccount',
  'ThawAccount',
  'TransferChecked',
  'ApproveChecked',
  'MintToChecked',
  'BurnChecked',
  'InitializeAccount2',
  'SyncNative',
  'InitializeAccount3',
  'InitializeMultisig2',
  'InitializeMint2',
  'GetAccountDataSize',
  'InitializeImmutableOwner',
  'AmountToUiAmount',
  'UiAmountToAmount',
  // Token-2022 only from here
  'InitializeMintCloseAuthority',
  'TransferFeeExtension',
  'ConfidentialTransferExtension',
  'DefaultAccountStateExtension',
  'Reallocate',
  'MemoTransferExtension',
  'CreateNativeMint',
  'InitializeNonTransferableMint',
  'InterestBearingMintExtension',
  'CpiGuardExtension',
  'InitializePermanentDelegate',
  'TransferHookExtension',
  'ConfidentialTransferFeeExtension',
  'WithdrawExcessLamports',
  'MetadataPointerExtension',
  'GroupPointerExtension',
  'GroupMemberPointerExtension',
  'ConfidentialMintBurnExtension',
  'ScaledUiAmountExtension',
  'PausableExtension',
] as const;

/** SPL Token / Token-2022 AuthorityType enum. */
export const TOKEN_AUTHORITY_TYPES = [
  'MintTokens',
  'FreezeAccount',
  'AccountOwner',
  'CloseAccount',
  'TransferFeeConfig',
  'WithheldWithdraw',
  'CloseMint',
  'InterestRate',
  'PermanentDelegate',
  'ConfidentialTransferMint',
  'TransferHookProgramId',
  'ConfidentialTransferFeeConfig',
  'MetadataPointer',
  'GroupPointer',
  'GroupMemberPointer',
  'ScaledUiAmount',
  'Pause',
] as const;

const STAKE_NAMES = [
  'Initialize',
  'Authorize',
  'DelegateStake',
  'Split',
  'Withdraw',
  'Deactivate',
  'SetLockup',
  'Merge',
  'AuthorizeWithSeed',
  'InitializeChecked',
  'AuthorizeChecked',
  'AuthorizeCheckedWithSeed',
  'SetLockupChecked',
  'GetMinimumDelegation',
  'DeactivateDelinquent',
  'Redelegate',
  'MoveStake',
  'MoveLamports',
] as const;

const LOADER_NAMES = [
  'InitializeBuffer',
  'Write',
  'DeployWithMaxDataLen',
  'Upgrade',
  'SetAuthority',
  'Close',
  'ExtendProgram',
  'SetAuthorityChecked',
  'Migrate',
  'ExtendProgramChecked',
] as const;

const STAKE_AUTHORIZE = ['Staker', 'Withdrawer'] as const;

function lamportsParams(lamports: bigint): Params {
  return { lamports: lamports.toString(), sol: formatSol(lamports) };
}

function camel(name: string): string {
  return name.charAt(0).toLowerCase() + name.slice(1);
}

function readTokenCOption(r: ByteReader): string | null {
  const tag = r.u8();
  return tag === 1 ? r.pubkey() : null;
}

interface PartIx {
  name: string;
  params: Params;
}

function decodeSystem(acc: (i: number) => string, data: Uint8Array): PartIx {
  const r = new ByteReader(data);
  const d = r.u32();
  const name = SYSTEM_NAMES[d];
  if (!name) return { name: `Instruction #${d}`, params: {} };
  const p: Params = {};
  switch (d) {
    case 0: // CreateAccount
      Object.assign(p, { from: acc(0), newAccount: acc(1) }, lamportsParams(r.u64()));
      p.space = r.u64().toString();
      p.owner = r.pubkey();
      break;
    case 1: // Assign
      p.account = acc(0);
      p.owner = r.pubkey();
      break;
    case 2: // Transfer
      Object.assign(p, { from: acc(0), to: acc(1) }, lamportsParams(r.u64()));
      break;
    case 3: {
      // CreateAccountWithSeed
      p.from = acc(0);
      p.newAccount = acc(1);
      p.base = r.pubkey();
      p.seed = r.bincodeString();
      Object.assign(p, lamportsParams(r.u64()));
      p.space = r.u64().toString();
      p.owner = r.pubkey();
      break;
    }
    case 4: // AdvanceNonceAccount
      p.nonceAccount = acc(0);
      p.nonceAuthority = acc(2);
      break;
    case 5: // WithdrawNonceAccount
      Object.assign(p, { nonceAccount: acc(0), to: acc(1), nonceAuthority: acc(4) }, lamportsParams(r.u64()));
      break;
    case 6: // InitializeNonceAccount
      p.nonceAccount = acc(0);
      p.nonceAuthority = r.pubkey();
      break;
    case 7: // AuthorizeNonceAccount
      p.nonceAccount = acc(0);
      p.nonceAuthority = acc(1);
      p.newAuthority = r.pubkey();
      break;
    case 8: // Allocate
      p.account = acc(0);
      p.space = r.u64().toString();
      break;
    case 9: // AllocateWithSeed
      p.account = acc(0);
      p.base = r.pubkey();
      p.seed = r.bincodeString();
      p.space = r.u64().toString();
      p.owner = r.pubkey();
      break;
    case 10: // AssignWithSeed
      p.account = acc(0);
      p.base = r.pubkey();
      p.seed = r.bincodeString();
      p.owner = r.pubkey();
      break;
    case 11: // TransferWithSeed
      Object.assign(p, { from: acc(0), base: acc(1), to: acc(2) }, lamportsParams(r.u64()));
      p.fromSeed = r.bincodeString();
      p.fromOwner = r.pubkey();
      break;
    case 12:
      p.nonceAccount = acc(0);
      break;
  }
  return { name, params: p };
}

function decodeToken(acc: (i: number) => string, data: Uint8Array): PartIx {
  const r = new ByteReader(data);
  const d = r.u8();
  const name = TOKEN_NAMES[d];
  if (!name) return { name: `Instruction #${d}`, params: {} };
  const p: Params = {};
  switch (d) {
    case 0: // InitializeMint
    case 20: {
      // InitializeMint2
      p.mint = acc(0);
      p.decimals = String(r.u8());
      p.mintAuthority = r.pubkey();
      const freeze = readTokenCOption(r);
      p.freezeAuthority = freeze ?? 'none';
      break;
    }
    case 1: // InitializeAccount
      Object.assign(p, { account: acc(0), mint: acc(1), owner: acc(2) });
      break;
    case 16: // InitializeAccount2
    case 18: // InitializeAccount3
      Object.assign(p, { account: acc(0), mint: acc(1) });
      p.owner = r.pubkey();
      break;
    case 3: // Transfer
      Object.assign(p, { source: acc(0), destination: acc(1), authority: acc(2) });
      p.amount = r.u64().toString();
      break;
    case 4: // Approve
      Object.assign(p, { source: acc(0), delegate: acc(1), owner: acc(2) });
      p.amount = r.u64().toString();
      break;
    case 5: // Revoke
      Object.assign(p, { source: acc(0), owner: acc(1) });
      break;
    case 6: {
      // SetAuthority
      const t = r.u8();
      p.account = acc(0);
      p.currentAuthority = acc(1);
      p.authorityType = TOKEN_AUTHORITY_TYPES[t] ?? `#${t}`;
      p.newAuthority = readTokenCOption(r) ?? 'none';
      return { name: `SetAuthority(${p.authorityType})`, params: p };
    }
    case 7: // MintTo
    case 14: // MintToChecked
      Object.assign(p, { mint: acc(0), account: acc(1), authority: acc(2) });
      p.amount = r.u64().toString();
      if (d === 14) p.decimals = String(r.u8());
      break;
    case 8: // Burn
    case 15: // BurnChecked
      Object.assign(p, { account: acc(0), mint: acc(1), authority: acc(2) });
      p.amount = r.u64().toString();
      if (d === 15) p.decimals = String(r.u8());
      break;
    case 9: // CloseAccount
      Object.assign(p, { account: acc(0), destination: acc(1), owner: acc(2) });
      break;
    case 10: // FreezeAccount
    case 11: // ThawAccount
      Object.assign(p, { account: acc(0), mint: acc(1), authority: acc(2) });
      break;
    case 12: // TransferChecked
      Object.assign(p, { source: acc(0), mint: acc(1), destination: acc(2), authority: acc(3) });
      p.amount = r.u64().toString();
      p.decimals = String(r.u8());
      break;
    case 13: // ApproveChecked
      Object.assign(p, { source: acc(0), mint: acc(1), delegate: acc(2), owner: acc(3) });
      p.amount = r.u64().toString();
      p.decimals = String(r.u8());
      break;
    case 17: // SyncNative
      p.account = acc(0);
      break;
    case 22: // InitializeImmutableOwner
      p.account = acc(0);
      break;
    case 25: // InitializeMintCloseAuthority
      p.mint = acc(0);
      p.closeAuthority = readTokenCOption(r) ?? 'none';
      break;
    case 26: {
      // TransferFeeExtension (Token-2022)
      const sub = r.u8();
      if (sub === 1 || (sub === 0 && r.remaining === 17 && acc(3) !== '?')) {
        Object.assign(p, { source: acc(0), mint: acc(1), destination: acc(2), authority: acc(3) });
        p.amount = r.u64().toString();
        p.decimals = String(r.u8());
        p.fee = r.u64().toString();
        return { name: 'TransferCheckedWithFee', params: p };
      }
      if (sub === 0) {
        p.mint = acc(0);
        p.transferFeeConfigAuthority = readTokenCOption(r) ?? 'none';
        p.withdrawWithheldAuthority = readTokenCOption(r) ?? 'none';
        p.transferFeeBasisPoints = String(r.u16());
        p.maximumFee = r.u64().toString();
        return { name: 'InitializeTransferFeeConfig', params: p };
      }
      break;
    }
    case 35: // InitializePermanentDelegate
      p.mint = acc(0);
      p.delegate = r.pubkey();
      break;
  }
  return { name, params: p };
}

function decodeStake(acc: (i: number) => string, data: Uint8Array): PartIx {
  const r = new ByteReader(data);
  const d = r.u32();
  const name = STAKE_NAMES[d];
  if (!name) return { name: `Instruction #${d}`, params: {} };
  const p: Params = { stakeAccount: acc(0) };
  const authKind = (n: number) => STAKE_AUTHORIZE[n] ?? `#${n}`;
  switch (d) {
    case 0: // Initialize
      p.staker = r.pubkey();
      p.withdrawer = r.pubkey();
      p.lockupUnixTimestamp = r.i64().toString();
      p.lockupEpoch = r.u64().toString();
      p.custodian = r.pubkey();
      break;
    case 1: // Authorize
      p.newAuthority = r.pubkey();
      p.authorityType = authKind(r.u32());
      p.currentAuthority = acc(2);
      break;
    case 2: // DelegateStake
      p.voteAccount = acc(1);
      p.authority = acc(5);
      break;
    case 3: // Split
      p.splitStakeAccount = acc(1);
      p.authority = acc(2);
      Object.assign(p, lamportsParams(r.u64()));
      break;
    case 4: // Withdraw
      p.to = acc(1);
      p.withdrawAuthority = acc(4);
      Object.assign(p, lamportsParams(r.u64()));
      break;
    case 5: // Deactivate
      p.authority = acc(2);
      break;
    case 7: // Merge
      p.destination = acc(0);
      p.source = acc(1);
      p.authority = acc(4);
      delete p.stakeAccount;
      break;
    case 8: // AuthorizeWithSeed
      p.newAuthority = r.pubkey();
      p.authorityType = authKind(r.u32());
      p.authoritySeed = r.bincodeString();
      p.authorityOwner = r.pubkey();
      p.authorityBase = acc(1);
      break;
    case 9: // InitializeChecked
      p.staker = acc(2);
      p.withdrawer = acc(3);
      break;
    case 10: // AuthorizeChecked
      p.authorityType = authKind(r.u32());
      p.currentAuthority = acc(2);
      p.newAuthority = acc(3);
      break;
    case 11: // AuthorizeCheckedWithSeed
      p.authorityType = authKind(r.u32());
      p.authoritySeed = r.bincodeString();
      p.authorityOwner = r.pubkey();
      p.authorityBase = acc(1);
      p.newAuthority = acc(3);
      break;
    case 16: // MoveStake
    case 17: // MoveLamports
      p.destination = acc(1);
      p.authority = acc(2);
      Object.assign(p, lamportsParams(r.u64()));
      break;
  }
  return { name, params: p };
}

function decodeLoader(acc: (i: number) => string, accounts: string[], data: Uint8Array): PartIx {
  const r = new ByteReader(data);
  const d = r.u32();
  const name = LOADER_NAMES[d];
  if (!name) return { name: `Instruction #${d}`, params: {} };
  const p: Params = {};
  switch (d) {
    case 0:
      p.buffer = acc(0);
      p.authority = acc(1);
      break;
    case 1:
      p.buffer = acc(0);
      p.authority = acc(1);
      p.offset = String(r.u32());
      break;
    case 2:
      p.payer = acc(0);
      p.programData = acc(1);
      p.program = acc(2);
      p.buffer = acc(3);
      p.authority = acc(7);
      p.maxDataLen = r.u64().toString();
      break;
    case 3:
      p.programData = acc(0);
      p.program = acc(1);
      p.buffer = acc(2);
      p.spill = acc(3);
      p.authority = acc(6);
      break;
    case 4: // SetAuthority (new authority optional → immutable)
    case 7: // SetAuthorityChecked
      p.account = acc(0);
      p.currentAuthority = acc(1);
      p.newAuthority = accounts[2] ?? 'none (immutable)';
      break;
    case 5:
      p.account = acc(0);
      p.recipient = acc(1);
      p.authority = acc(2);
      if (accounts[3]) p.program = accounts[3];
      break;
    case 6:
    case 9:
      p.programData = acc(0);
      p.program = acc(1);
      p.additionalBytes = String(r.u32());
      break;
  }
  return { name, params: p };
}

function decodeComputeBudget(data: Uint8Array): PartIx {
  const r = new ByteReader(data);
  const d = r.u8();
  switch (d) {
    case 0:
      return { name: 'RequestUnits', params: { units: String(r.u32()), additionalFee: String(r.u32()) } };
    case 1:
      return { name: 'RequestHeapFrame', params: { bytes: String(r.u32()) } };
    case 2:
      return { name: 'SetComputeUnitLimit', params: { units: String(r.u32()) } };
    case 3:
      return { name: 'SetComputeUnitPrice', params: { microLamports: r.u64().toString() } };
    case 4:
      return { name: 'SetLoadedAccountsDataSizeLimit', params: { bytes: String(r.u32()) } };
    default:
      return { name: `Instruction #${d}`, params: {} };
  }
}

function decodeAta(acc: (i: number) => string, data: Uint8Array): PartIx {
  const d = data.length === 0 ? 0 : data[0];
  if (d === 0 || d === 1) {
    return {
      name: d === 0 ? 'Create' : 'CreateIdempotent',
      params: { payer: acc(0), account: acc(1), owner: acc(2), mint: acc(3) },
    };
  }
  if (d === 2) {
    return { name: 'RecoverNested', params: { destination: acc(2), wallet: acc(5) } };
  }
  return { name: `Instruction #${d}`, params: {} };
}

function decodeMemo(data: Uint8Array): PartIx {
  try {
    return { name: 'Memo', params: { text: new TextDecoder('utf-8', { fatal: true }).decode(data) } };
  } catch {
    return { name: 'Memo', params: { bytes: String(data.length) } };
  }
}

const PREFIX: Record<string, string> = {
  [SYSTEM_PROGRAM_ID]: 'System',
  [TOKEN_PROGRAM_ID]: 'Token',
  [TOKEN_2022_PROGRAM_ID]: 'Token-2022',
  [STAKE_PROGRAM_ID]: 'Stake',
  [BPF_UPGRADEABLE_LOADER_ID]: 'Loader',
  [COMPUTE_BUDGET_PROGRAM_ID]: 'ComputeBudget',
  [ASSOCIATED_TOKEN_PROGRAM_ID]: 'ATA',
  [MEMO_PROGRAM_ID]: 'Memo',
  [MEMO_V1_PROGRAM_ID]: 'Memo',
};

const TYPE_NS: Record<string, string> = {
  [SYSTEM_PROGRAM_ID]: 'system',
  [TOKEN_PROGRAM_ID]: 'token',
  [TOKEN_2022_PROGRAM_ID]: 'token',
  [STAKE_PROGRAM_ID]: 'stake',
  [BPF_UPGRADEABLE_LOADER_ID]: 'loader',
  [COMPUTE_BUDGET_PROGRAM_ID]: 'computeBudget',
  [ASSOCIATED_TOKEN_PROGRAM_ID]: 'ata',
  [MEMO_PROGRAM_ID]: 'memo',
  [MEMO_V1_PROGRAM_ID]: 'memo',
};

/** Decode one instruction. Never throws. */
export function decodeInstruction(programId: string, accounts: string[], data: Uint8Array, inner = false): DecodedIx {
  const programName = knownProgram(programId)?.name;
  const acc = (i: number): string => accounts[i] ?? '?';
  const prefix = Object.hasOwn(PREFIX, programId) ? PREFIX[programId] : undefined;
  const ns = Object.hasOwn(TYPE_NS, programId) ? TYPE_NS[programId] : undefined;
  const base = { programId, programName, accounts, ...(inner ? { inner: true } : {}) };

  if (!prefix || !ns) {
    return {
      ...base,
      name: programName ? `${programName}: Instruction` : 'Unknown',
      type: programName ? 'known' : 'unknown',
      params: { accounts: String(accounts.length), dataBytes: String(data.length) },
    };
  }

  try {
    let part: PartIx;
    switch (ns) {
      case 'system':
        part = decodeSystem(acc, data);
        break;
      case 'token':
        part = decodeToken(acc, data);
        break;
      case 'stake':
        part = decodeStake(acc, data);
        break;
      case 'loader':
        part = decodeLoader(acc, accounts, data);
        break;
      case 'computeBudget':
        part = decodeComputeBudget(data);
        break;
      case 'ata':
        part = decodeAta(acc, data);
        break;
      default:
        part = decodeMemo(data);
    }
    const bare = part.name.replace(/\(.*\)$/, '');
    return {
      ...base,
      name: `${prefix}: ${part.name}`,
      type: `${ns}:${camel(bare)}`,
      params: part.params,
    };
  } catch {
    return { ...base, name: `${prefix}: Unparseable`, type: `${ns}:unparseable`, params: { dataBytes: String(data.length) } };
  }
}
