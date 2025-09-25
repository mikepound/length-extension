# Java SHA-256 Length Extension Demo
This Java project is a demonstration of a length extension attack on a message authentication code using the SHA-256 hash function. This project was used in the two videos on SHA-2 length extension attacks flaws on the [Computerphile](https://www.youtube.com/Computerphile) YouTube channel. [SHA-2 Fatal Flaw?](https://www.youtube.com/watch?v=gOIBUe1fjX0) and [Coding a SHA-2 Length Extension Attack](https://www.youtube.com/watch?v=XQo6rLdFlCg).

# Code License and Use
This code is released without restriction into the public domain, as per the license. I am not intending on improving or otherwise extending this code at this time, it is purely a demonstration.

# Running the code
You will need to have a Java runtime environment installed. You can then build and run the project using gradle, with the `gradlew build` and `gradlew run` commands. You may find it easier to use [IntelliJ IDEA](https://www.jetbrains.com/idea/), which should load the project and run it easily.

The attack itself is found in the `Main.main()` method.

# How the attack works
Most of the attack is covered in the above videos. The general steps for the attack are as follows:
1. Bank A authenticates a message using a secret key. This involves coputing a hash of the key and the transction message, h(k|m). As part of this process, the SHA-256 hash will add padding to this message.
2. We create an array of bytes representing what this old padding would have been.
3. We create a new transaction amount to add on the end of our transaction message, which we call x. This hopes that the parser reads the new amount and ignores the old one.
4. We create a new extended transaction of the original m, the old padding op, and the new attack payload x.
5. We extend the original hash h(k|m) to be h(k|m|op|x), to match the new transaction.
6. We overrite the old message and old authentication hash with the new values.
7. Bank B verifies the new message as authentic, because the extended message is provided with a valid recomputed hash. This was done without access to the shared secret held by banks A and B.

If you comment out the attack code, you will see that the original transaction verifies correctly. Simialrly, if you edit the message without also correcting the hash, you will see that authentication fails.

# Preventing Length Extensions
For anyone building systems using authentication, consider using either public key schemes, or the safer [HMAC](https://www.youtube.com/watch?v=wlSG3pEiQdc) scheme. It is also crucial to never assume that any part of the system is unbreakable, a normal verification scheme would need to detect incorrect or duplicate amounts to reject the flawed extended transaction, rather than accepting the new amount without question.

