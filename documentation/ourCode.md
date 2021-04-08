### Memory Used ###

asdf;lkj

### Explanation ###

The `headerStructure` in the header file holds all the data that is needed to extract data from the packets. The `format_code` enum holds the codes that the packets come to identify what the packet looks like.  To add a new format, add a new code to the enum, and also add this to the switch in `workOnPCAPS()`, now we can jump to a function which extracts the times from a packet in this format just like `extractTimeAristaFormat()`. Another namespace corresponding to this format should be added that has all the information pertinent to that format, such as the position of the times, the structure of the times etc.