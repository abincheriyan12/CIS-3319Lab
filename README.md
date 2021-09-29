# CIS-3319Lab

Lab 2: Implementation and Application of HMAC







HMAC is a keyed-hash type of message authentication code (MAC), involving a hash function and a secret key. It can simultaneously provide the data integrity and the authentication of a message. According to the different underlying hash functions MD5, SHA-1, SHA-256, etc., the algorithm is termed HMAC-MD5, HMAC-SHA1, HMAC-SHA256, etc.TaskIt is an individualwork using socket programming. ClientCand Server Sshare a key for HMAC in anoffline manner (e.g., a local file). Client Cthen generates a message, gets the HMAC digest of this message, and encryptsthe message along with its HMAC to obtain ciphertext. Then Csends this ciphertext to ServerS. ServerSdecrypts received ciphertext and then verifies the integrity of the received message by generating another HMAC with the shared HMAC key and matchesthe two HMACs. Client Cand Server Sswitch the roles and do the above again. All the transmitted messages should be encrypted with DES.
