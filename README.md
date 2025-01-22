## Solana-2FA-Wallet-Program  

I don't think this is secure 100% yet, but I can't seem to find any way it could be circumvented. Maybe with more brains we can make it bulletproof.

## How It (Might) Work  

1. Client generates a random 32 bytes and prints out secret to import to Google Authenticator
2. Client encrypts secret using a signed message consisting of ["2FA_AUTH", nonce]
3. Client calls initialize function, wallet program stores the encrypted secret key in a PDA and opens a wallet PDA
4. User is free to deposit any amount of sol to the PDA via transfers as usual
5. To withdraw the user supplies a TOTP passcode from Google Authenticator in instruction data
6. Wallet program uses Ed25519 program to get and verify the signature of the message + nonce
7. Wallet program checks for correct signer, and caller, and decrypts the secret with the signature
8. Wallet program derives the current TOTP given the 30 second time window, and if matches supplied, allows the transfer
9. Wallet program re-encrypts the secret key with nonce + 1 and writes it to the auth pda for use in the next transaction


A few of these steps are not implemented correctly 


PR's encouraged  

[Any Q's find me on Twitter same username](https://x.com/retardedchaddev)
