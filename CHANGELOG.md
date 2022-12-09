# CHANGELOG: pocket-messaging

## [2.0.0] - 20221209
Add shared SocketFactoryStats usage to HandshakeFactory.  
Change Messaging.send call signature for timeout to be strictly number (breaking call signature change).  
Add Messaging.isMessagePending function.  
Add pocket-console as logging utility.  
npm audit fix on external dependency.  
Add maxConnectionsPerClientPair limit to HandshakeFactory.  
Add ping functionality for more aggressive disconnection detection.  
Change ErrorEvent.error type from Buffer to string.  

## [1.1.0] - 20221010
Bug fix: Properly close underlaying socket of unopened Messaging instance.  
Add Handshakefactory + tests.  
Bump dependency on pocket-sockets to version 1.2.0.  
Allow peerData to be function for just-in-time peer-data creation.  
Add tests.  

## [1.0.2] - 20220516
Add project and compiler options.  

## [1.0.1] - 20220516
Update pocket-sockets version.  

## [1.0.0] - 20220516
Switch to using pocket-sockets on npm instead of local disk.  
Update dependency version.  
Add own longtermPk to HandshakeResult.  
Allow for variable length of sent client/serverData.  
Add sessionId to resulting HandshakeParams.  
Introduce native ddos mitigation.  
Add type HandshakeResult.  
Add clearTimeout * Refactor MIXED to ANY.  
Replace tweetnacl, tweetnacl-auth and ed2curve with libsodium.  
Update Handshake to fix potential timing and length extension vulnerabilities.  
Update tests.  
Fix bug about buffered messages being consumed in reverse order.  
Update API to be more clear and easy to use.  
Adjust test.  
Add box/unbox test.  
Improve error handling on unbox.  
Add code comments.  
Fix bug in unbox, wrong nonce returned.  
Send MixedEvent also for Timeout events.  
Add replyCounter and timeoutStream.  
Remove commented out code.  
Update Messaging to work with new Crypto.ts.  
Update package.json.  
Add Handshake.ts as an optional four-way handshake protocol.  
Add example, documentation export and update code to reflect changes to dependencies.  
Add more tests around Messaging procedures.  
Set isClosed flag as part of Messaging close and add new set of tests.  
Add more tests around Messaging procedures.  
Add more tests around Messaging procedures.  
Add new verifications to Messaging set of tests.  
Move EventType from Messaging.ts to types.ts.  

## [0.9.0] - 20210829
First release.
