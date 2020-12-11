# 2 - S3 Bucket Wrapper
## Objective
Find an open s3 bucket which has the flag in it, then extract the contents of the flag.

## Part 1 - S3 Bucket
The initial challenge leads of with some hints in the terminal and seeding the system with `bucket_finder.rb` which will search AWS S3 for open buckets from a specified wordlist. An example wordlist is provided which does not have the match. The crux of this first part is to construct a wordlist. In the motd banner that welcomes the user to the terminal has highlighed in green some clue text. After adding variations to the wordlist, the open s3 bucket was discoverd.

### wordlist
```
private-kringlecastle
private-wrapper
private-santa
private-Wrapper3000
private-Wrapper
private-3000
3000-private
kringlecastle-private
wrapper-private
santa-private
Wrapper3000-private
Wrapper-private
3000-private
dev-wrapper-3000
wrapper-dev
ribbon
curling
ribbon-curl
ribbon-curling
package
wrap-package
wrapping-package
package-wrapper
package-wrapping
package-wrap
wrapper-3000
wrapper3000
```

The open bucket was discovered to be `http://s3.amazonaws.com/wrapper3000/package`

## Unwrapping the Flag
The downloaded file is just ascii text as per the output of the `file` command. Looking over the characters, it looks like it might be base64 encoded. This can be verified by piping the output into `base64 -D` (mac) or `base64 -d` (linux). If no errors occur, it was a valid encoding. Doing this, it was seen to be valid base64 encoding of a different file type.

```bash
curl http://s3.amazonaws.com/wrapper3000/package --silent | base64 -D | tee package
```

The new file decoded appears to be zip file, detected via the `file` command or looking at the first 4 magic bytes ascii as .PK. which is zip. Unzipped with:

```bash
unzip package
```

The newly unzipped file is a bzip2 file now, which can be unzipped via tar.
```bash
tar -xjvf package.txt.Z.xz.xxd.tar.bz2
```

The resultant file is now an xxd dump of a file which needs to be re-assembled into it's binary representation as seen below.
```bash
xxd -r tar package.txt.Z.xz.xxd.tar.bz2
```

Now, we are left with an xz archive file which can be decompressed as below.
```bash
xz -d package.txt.Z.xz
```

Finally, the last layer of obfuscation can be removed using the old `uncompress` command.
```bash
uncompress package.txt.Z
```

Which leaves us with the package.txt file which can be `cat`ed out to see the flag:
`North Pole: The Frostiest Place on Earth`
