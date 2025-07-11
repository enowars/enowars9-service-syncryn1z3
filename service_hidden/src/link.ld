PHDRS {
  interp PT_INTERP;
  text PT_LOAD;
  ext PT_LOAD FLAGS(0x7);
  data PT_LOAD;
  dynamic PT_DYNAMIC;
}

SECTIONS {
  . = 0x0;

  .interp : {
    *(.interp)
  } :text :interp

  .text : {
    *(.text)
  } :text

  .rodata : {
    *(.rodata)
  } :text

  . = . + 0x1000;

  /* Boy, do I hope this doesn't lead to RCE */
  .ext : {
    *(.ext)
  } :ext
  
  . = . + 0x1000;

  .data : {
    *(.data)
  } :data
  
  .dynamic : {
    *(.dynamic)
  } :data :dynamic
}
