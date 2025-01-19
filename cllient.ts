import {
    Connection,
    Keypair,
    PublicKey,
    SystemProgram,
    Transaction,
    TransactionInstruction,
    sendAndConfirmTransaction,
    LAMPORTS_PER_SOL,
ComputeBudgetProgram
} from '@solana/web3.js';
import util from "tweetnacl-util"
import nacl from "tweetnacl";
import { Ed25519Program } from '@solana/web3.js';
import * as crypto from 'crypto';
import { authenticator } from 'otplib';
import pkg from 'hi-base32';
import BN from 'bn.js';
const { encode } = pkg;
const compute = ComputeBudgetProgram.setComputeUnitPrice({microLamports: 1000000})
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
export class TwoFactorWallet {
    constructor(
        connection,
        owner,
        programId
    ) {
        this.connection = connection;
        this.owner = owner;
        this.programId = programId;

        // derive pdas
        [this.authPda, this.authBump] = PublicKey.findProgramAddressSync(
            [Buffer.from('auth'), owner.publicKey.toBuffer()],
            programId
        );

        [this.walletPda, this.walletBump] = PublicKey.findProgramAddressSync(
            [Buffer.from('wallet'), owner.publicKey.toBuffer()],
            programId
        );
    }

    async initialize() {
        const balance = await this.connection.getBalance(this.owner.publicKey);
      
        // generate random 32-byte secret key
        this.secretKey = crypto.randomBytes(32);

        // sign message for initial encryption
        const message = Buffer.from('2FA_AUTH');
        const signature =  nacl.sign.detached(message, this.owner.secretKey)

        // encrypt secret key
        const nonce = 0;
        const encryptedKey = this.encryptKey(this.secretKey, nonce, Buffer.from(signature.slice(0, 32).toString("hex")));

        const instruction = new TransactionInstruction({
            keys: [
                { pubkey: this.owner.publicKey, isSigner: true, isWritable: true },
                { pubkey: this.authPda, isSigner: false, isWritable: true },
                { pubkey: this.walletPda, isSigner: false, isWritable: true },
                { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            ],
            programId: this.programId,
            data: Buffer.concat([
                Buffer.from([0]),
                encryptedKey,
            ]),
        });

        console.log("Initialize instruction data length:", instruction.data.length);
        console.log("Encrypted key length:", encryptedKey.length);

        const transaction = new Transaction().add(instruction);
        await sendAndConfirmTransaction(this.connection, transaction, [this.owner]);

        // return totp urp for qr code / google authenticator
        const encodedSecret = encode(Buffer.from(this.secretKey));
        return authenticator.keyuri(
            this.owner.publicKey.toString(),
            'Solana 2FA Wallet',
            encodedSecret
        );
    }

    async getBalance() {
        return await this.connection.getBalance(this.walletPda);
    }

    async executeTransaction(recipient, amount) {
      
        if (!(recipient instanceof PublicKey)) {
            recipient = new PublicKey(recipient);
        }

        // sign message for Ed25519 verification
        const message = Buffer.from('2FA_AUTH');
        const signature = nacl.sign.detached(message, this.owner.secretKey)

        // create ed25519 verification instruction
        const ed25519Instruction = Ed25519Program.createInstructionWithPublicKey({
            publicKey: this.owner.publicKey.toBytes(),
            message: message,
            signature: signature,
            instructionIndex: 0
        });

        // get the auth account data
        const authAccount = await this.connection.getAccountInfo(this.authPda);
        if (!authAccount) {
            throw new Error("Auth account not found. Please initialize the wallet first.");
        }

        // extract encrypted key and nonce
        const encryptedKey = authAccount.data.slice(0, 32);
        const nonce = authAccount.data.readBigUInt64LE(32);
		console.log(nonce, signature.toString("hex"))
        // decrypt using the same signature that will be verified on-chain
        const secretKey = this.decryptKey(encryptedKey, Number(nonce), Buffer.from(signature).slice(0, 32));

        const TIME_STEP = 30; // must match program time_step
        const currentTime = Math.floor(Date.now() / 1000);
        const counter = Math.floor(currentTime / TIME_STEP);

        console.log('Client time:', currentTime);
        console.log('Client counter:', counter);

        // Log the secret key being used
        console.log('Client secret key (hex):', secretKey.toString('hex'));
        console.log('Client secret key (bytes):', [...secretKey]);

        const encodedSecret = encode(Buffer.from(secretKey));
        console.log('Client base32 encoded secret:', encodedSecret);

        const totp = authenticator.generate(encodedSecret);
        console.log('Generated TOTP:', totp);
        console.log('TOTP bytes:', Buffer.from(totp).toString('hex'));

        // convert totp to buffer
        const totpBuffer = Buffer.alloc(8);
        new BN(totp).toArrayLike(Buffer, 'le', 8).copy(totpBuffer);
        const amountBuffer = Buffer.alloc(8);
        new BN(amount).toArrayLike(Buffer, 'le', 8).copy(amountBuffer);

        const instructionData = Buffer.concat([
            Buffer.from([1]),
            totpBuffer,
            amountBuffer,
        ]);

        console.log("Instruction data:", {
            tag: instructionData[0],
            totp: totpBuffer.toString('hex'),
            amount: amountBuffer.toString('hex'),
            totalLength: instructionData.length
        });

		console.log(this.walletPda.toString())
        const programInstruction = new TransactionInstruction({
            keys: [
                { pubkey: this.owner.publicKey, isSigner: true, isWritable: false },
                { pubkey: this.authPda, isSigner: false, isWritable: true },
                { pubkey: this.walletPda, isSigner: false, isWritable: true },
                { pubkey: recipient, isSigner: false, isWritable: true },
                { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
                { pubkey: new PublicKey('Sysvar1nstructions1111111111111111111111111'), isSigner: false, isWritable: false },
            ],
            programId: this.programId,
            data: instructionData,
        });

        try {
            const transaction = new Transaction()
                .add(ed25519Instruction)
                .add(programInstruction);

            console.log("TOTP being sent:", totp);
            console.log("TOTP buffer:", totpBuffer);
            console.log("Amount being sent:", amount);
            console.log("Instruction data:", programInstruction.data);

            const signature = await sendAndConfirmTransaction(
                this.connection,
                transaction,
                [this.owner],
                {
                    skipPreflight: false,
                    preflightCommitment: 'confirmed'
                }
            );
            console.log("Transaction successful:", signature);
            return signature;
        } catch (error) {
            console.error("Transaction failed:", error);
            if (error.logs) {
                console.error("Program logs:", error.logs);
            }
            throw error;
        }
    }

    encryptKey(key, nonce, signature) {
        const result = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) {
            result[i] = key[i] ^ signature[i] ^ ((nonce >> (i % 8)) & 0xFF);
        }
        return result;
    }

    decryptKey(encryptedKey, nonce, signature) {
        const result = Buffer.alloc(32);
        for (let i = 0; i < 32; i++) {
            result[i] = encryptedKey[i] ^ signature[i] ^ ((nonce >> (i % 8)) & 0xFF);
        }
        return result;
    }
}

const connection = new Connection("https://api.devnet.solana.com");
const owner = Keypair.fromSecretKey(Uint8Array.from([192, 94, 192, ...]))
const programId = new PublicKey("program id");

const wallet = new TwoFactorWallet(connection, owner, programId);

// initialize wallet
const totpUri = await wallet.initialize();
console.log("TOTP URI for QR code:", totpUri);
 await wait(20000)
// check balances
const balance = await wallet.getBalance();
console.log("Wallet balance:", balance / LAMPORTS_PER_SOL, "SOL");

// execute transaction
const recipient = new PublicKey("recipient");
const amount = 0.1 * LAMPORTS_PER_SOL; // 0.1 sol
await wallet.executeTransaction(recipient, amount);
