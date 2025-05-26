Service documentation
======================

## Flagstores
There exist two flagstores:
1. User description of port secured by HMAC
2. User description of port secured by plaintext secret

## Vulnerabilities & Exploits

### 1. Return value leak
#### Overview
- Difficulty: easy
- Replayable: no

#### Description
Return value of memcmp during ICV verification is leaked.

#### Exploit
Start with an ICV of all zeros. This will result in the server returning the first byte of the ICV. Now send the leaked byte followed by zeros to leak the second byte. This process is continued until the entire ICV is known.
This simple implementation will work approx. 94% of the time. This is because at every byte there is a 1/256 chance that it is zero. In this case the server will not leak the expected byte. We therefore need to verify every byte by also testing with another value at every position (e.g. 0x01). If the difference between both tests is not 1, we know that the wanted byte is either 0 or 1. We therefore test with yet another value (e.g. 0x0a, 0x02 will not always work*) which one it ultimately is.
This still doesnt work on every ICV however. If the sequence 0x00 0x02 exists in the ICV, the existing logic will return the value 0x02 for the first byte, without performing the third check. That is why the logic must be adapted to include a third check whenever the value 0x02 is expected.
It is also possible to slightly change the request message which will produce a different ICV. Repeat this until the currently implemented logic succeeds.


### 2. Integer signed conversion
#### Overview
- Difficulty: medium
- Replayable: no

#### Description
Integer signed conversion during TLV parsing.

#### Exploit
Send a (garbage) management frame to the target port_id. The server will return a management frame indicating an error that is signed with an authentication TLV. However the signature only covers part of the frame. The padding at the end the frame can be modified. The attacker can now insert a request TLV for the flag into the padding followed by a padding TLV with a negative length. The attacker can now send the packet back to the server. During parsing the valid authentication TLV will be duplicated due to the negative length. The following logic will therefore interpret the malicious request to be signed correctly and return the flag.
```
Server response:
| Header | Management TLV | Authentication TLV |             Padding TLV            |
<------------ Autheticated content ------------>

Altered request:
| Header | Management TLV | Authentication TLV | Malicius Padding TLV | Padding TLV |
                                                                      | Length: -XX |
                          <----------------- XX bytes ---------------->

Parsing result of altered request:
| Header | Management TLV | Authentication TLV | Malicius Padding TLV | Padding TLV | Authentication TLV (again) | ... |
<--------------------------------------------- Autheticated content --------------------------------------------->
```

### 3. Zero-length ICV
#### Overview
- Difficulty: easy
- Replayable: yes

#### Description
The ICV (HMAC) comparison uses the user-supplied length of the ICV, instead of a fixed value.

#### Exploit
Send an authentication TLV with an ICV of length zero.


### 4. Timing of strcmp calls
#### Overview
- Difficulty: hard
- Replayable: no

#### Description
The execution time of the strcmp function used by the service varies depending on how much of the compared strings are matching.

#### Exploit
Send an authentication TLV between two GET TIME management TLVs. This will leak quite accurate measurements of the strcmp function used to compare the supplied secret with the actual one. Repeat this for every possible character at a given position. Now take the character that had the longest execution time to leak the secret character by character.
Even though the time measurements are very accurate, the execution time is also subject to noise. A backtracking algorithm must therefore be used to detect faults.
