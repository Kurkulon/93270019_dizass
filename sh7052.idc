#include <idc.idc>

// This script will, with a bit of operator assistance, automatically
// disassemble an SH7052F ROM image into a format that should be ALMOST
// presentable to the GNU binutils assembler.
//
// Most of the addresses mentioned in here were drawn from the Renesas
// documentation at:
//
// http://documentation.renesas.com/eng/products/mpumcu/rej09b0171_superh.pdf
//
// This was developed using IDA Pro Advanced, version 5.2; different
// versions may behave differently, and because this script does very
// little error checking, you should only use this on a database you
// don't mind completely destroying.
//
// STEP-BY-STEP TO DISASSEMBLING YOUR ROM IMAGE:
//
// Run "idaw -psh4b <rom image filename>" (use "udal" on Linux). (Another
//   option would be to open IDA Pro, drag your ROM image onto the main
//   window, and choose the "Hitachi SH4B" processor.)
//
// Accept the default options for segments, analysis, etc. Don't bother
//   creating a RAM segment; this script will do it for you.
//
// Once you are presented with the main disassembly view window,
//   go to the "Options" drop-down menu, and select "Target assembler...".
//   Choose "GNU Assembler" when asked. (If you happen to have a copy of
//   SHASM, feel free to leave this alone, but most people will want to
//   use the free GNU assembler for the SH-ELF platform.)
//
// Next, go to the "Options" drop-down meny, and select "Analysis options...".
//   Choose "Kernel analyzer options 1", and uncheck:
//     "Create ascii string if data xref exists"
//     "Create offset if data xref to seg32 exists"
//   Choose "Kernel analyzer options 2", and uncheck:
//     "Check for unicode strings"
//   (There are no ASCII or Unicode strings in a typical SH7052F ROM image,
//   and IDA doesn't take alignment into account when converting referenced
//   32-bit values to offsets for some reason.)
//
// Finally, go to the "File" drop-down menu, select "Load file", select
//   "IDC file...", and choose this script. It will automatically start
//   disassembling the ROM, labeling known memory, register, and function
//   addresses as it goes.

static main() {
  Message("\nStarting ROM processing.\n");
  fix_segments();
  hardware_registers();
  size_interrupts();
  name_interrupts();
  trace_interrupts();
  Message("Finished ROM processing.\n");
}

static fix_segments() {
  // Give the ROM segment a name if it doesn't have one already.
  SegRename(0x0, "ROM");

  // Create a segment for RAM.
  SegCreate(0xFFFF8000, 0xFFFFAFFF, 0x0, 0x1, saAbs, scStack);
  SegRename(0xFFFF8000, "RAM");

  // Create a segment for the hardware registers.
  SegCreate(0xFFFFE400, 0xFFFFF85F, 0x0, 0x1, saAbs, scStack);
  SegRename(0xFFFFE400, "HWREG");
}

static size_interrupts() {
  auto i;

  Message("Sizing interrupt vectors...");
  for (i=0; i < 0x400; i=i+4) {
    if (!MakeDword(i)) {
      Warning("Failed to size interrupt vector 0x%x.\n", i);
    }
  }
  Message("done.\n");
}

static trace_interrupts() {
  auto i;

  Message("Tracing interrupt vectors...");
  for (i=0; i < 0x400; i=i+4) {
    // Stack pointers aren't code.
    if(i == 0x4 || i == 0xC) {
      continue;
    }

    if (!MakeCode(Dword(i))) {
      Warning("Could not create code at interrupt 0x%x.\n", i);
    }
  }
  Wait();
  Message("done.\n");
}

static name_vector(ea, vec, tar) {
  if (!MakeName(ea, vec)) {
    Warning("Failed to name vector 0x%x \"%s\".\n", ea, tar);
  }
  if (tar != "" && Name(Dword(ea)) == "") {
    if (!MakeName(Dword(ea), tar)) {
      Warning("Failed to name vector \"%s\" target \"%s\".\n", vec, tar);
    }
  }
}

static name_interrupts() {
  Message("Naming interrupt vectors...");
  name_vector(0x00000000, "v_power_on_pc", "init");
  name_vector(0x00000004, "v_power_on_sp", "stack");
  name_vector(0x00000008, "v_reset_pc", "reset_pc");
  name_vector(0x0000000C, "v_reset_sp", "reset_sp");
  name_vector(0x00000010, "v_gen_ill_inst", "reset");
  name_vector(0x00000018, "v_slot_ill_inst", "slot_ill_inst");
  name_vector(0x00000024, "v_cpu_addr_err", "cpu_addr_err");
  name_vector(0x00000028, "v_dmac_addr_err", "dmac_addr_err");
  name_vector(0x0000002C, "v_int_nmi", "int_nmi");
  name_vector(0x00000030, "v_int_userbreak", "int_userbreak");
  name_vector(0x00000100, "v_int_irq0", "int_irq0");
  name_vector(0x00000104, "v_int_irq1", "int_irq1");
  name_vector(0x00000108, "v_int_irq2", "int_irq2");
  name_vector(0x0000010C, "v_int_irq3", "int_irq3");
  name_vector(0x00000120, "v_dmac0_dei0", "dmac0_dei0");
  name_vector(0x00000128, "v_dmac1_dei1", "dmac1_dei1");
  name_vector(0x00000130, "v_dmac2_dei2", "dmac2_dei2");
  name_vector(0x00000138, "v_dmac3_dei3", "dmac3_dei3");
  name_vector(0x00000140, "v_atu01_itv1", "atu01_itv1");
  name_vector(0x00000150, "v_atu02_ici0A", "atu02_ici0A");
  name_vector(0x00000158, "v_atu02_ici0B", "atu02_ici0B");
  name_vector(0x00000160, "v_atu03_ici0C", "atu03_ici0C");
  name_vector(0x00000168, "v_atu03_ici0D", "atu03_ici0D");
  name_vector(0x00000170, "v_atu04_ovi0", "atu04_ovi0");
  name_vector(0x00000180, "v_atu11_imi1A", "atu11_imi1A");
  name_vector(0x00000184, "v_atu11_imi1B", "atu11_imi1B");
  name_vector(0x00000188, "v_atu11_imi1C", "atu11_imi1C");
  name_vector(0x0000018C, "v_atu11_imi1D", "atu11_imi1D");
  name_vector(0x00000190, "v_atu12_imi1E", "atu12_imi1E");
  name_vector(0x00000194, "v_atu12_imi1F", "atu12_imi1F");
  name_vector(0x00000198, "v_atu12_imi1G", "atu12_imi1G");
  name_vector(0x0000019C, "v_atu12_imi1H", "atu12_imi1H");
  name_vector(0x000001A0, "v_atu13_ovi1AB", "atu13_ovi1AB");
  name_vector(0x000001B0, "v_atu21_imi2A", "atu21_imi2A");
  name_vector(0x000001B4, "v_atu21_imi2B", "atu21_imi2B");
  name_vector(0x000001B8, "v_atu21_imi2C", "atu21_imi2C");
  name_vector(0x000001BC, "v_atu21_imi2D", "atu21_imi2D");
  name_vector(0x000001C0, "v_atu22_imi2E", "atu22_imi2E");
  name_vector(0x000001C4, "v_atu22_imi2F", "atu22_imi2F");
  name_vector(0x000001C8, "v_atu22_imi2G", "atu22_imi2G");
  name_vector(0x000001CC, "v_atu22_imi2H", "atu22_imi2H");
  name_vector(0x000001D0, "v_atu23_ovi2AB", "atu23_ovi2AB");
  name_vector(0x000001E0, "v_atu31_imi3A", "atu31_imi3A");
  name_vector(0x000001E4, "v_atu31_imi3B", "atu31_imi3B");
  name_vector(0x000001E8, "v_atu31_imi3C", "atu31_imi3C");
  name_vector(0x000001EC, "v_atu31_imi3D", "atu31_imi3D");
  name_vector(0x000001F0, "v_atu32_ovi3", "atu32_ovi3");
  name_vector(0x00000200, "v_atu41_imi4A", "atu41_imi4A");
  name_vector(0x00000204, "v_atu41_imi4B", "atu41_imi4B");
  name_vector(0x00000208, "v_atu41_imi4C", "atu41_imi4C");
  name_vector(0x0000020C, "v_atu41_imi4D", "atu41_imi4D");
  name_vector(0x00000210, "v_atu42_ovi4", "atu42_ovi4");
  name_vector(0x00000220, "v_atu51_imi5A", "atu51_imi5A");
  name_vector(0x00000224, "v_atu51_imi5B", "atu51_imi5B");
  name_vector(0x00000228, "v_atu51_imi5C", "atu51_imi5C");
  name_vector(0x0000022C, "v_atu51_imi5D", "atu51_imi5D");
  name_vector(0x00000230, "v_atu52_ovi5", "atu52_ovi5");
  name_vector(0x00000240, "v_atu6_cmi6A", "atu6_cmi6A");
  name_vector(0x00000244, "v_atu6_cmi6B", "atu6_cmi6B");
  name_vector(0x00000248, "v_atu6_cmi6C", "atu6_cmi6C");
  name_vector(0x0000024C, "v_atu6_cmi6D", "atu6_cmi6D");
  name_vector(0x00000250, "v_atu7_cmi7A", "atu7_cmi7A");
  name_vector(0x00000254, "v_atu7_cmi7B", "atu7_cmi7B");
  name_vector(0x00000258, "v_atu7_cmi7C", "atu7_cmi7C");
  name_vector(0x0000025C, "v_atu7_cmi7D", "atu7_cmi7D");
  name_vector(0x00000260, "v_atu81_osi8A", "atu81_osi8A");
  name_vector(0x00000264, "v_atu81_osi8B", "atu81_osi8B");
  name_vector(0x00000268, "v_atu81_osi8C", "atu81_osi8C");
  name_vector(0x0000026C, "v_atu81_osi8D", "atu81_osi8D");
  name_vector(0x00000270, "v_atu82_osi8E", "atu82_osi8E");
  name_vector(0x00000274, "v_atu82_osi8F", "atu82_osi8F");
  name_vector(0x00000278, "v_atu82_osi8G", "atu82_osi8G");
  name_vector(0x0000027C, "v_atu82_osi8H", "atu82_osi8H");
  name_vector(0x00000280, "v_atu83_osi8I", "atu83_osi8I");
  name_vector(0x00000284, "v_atu83_osi8J", "atu83_osi8J");
  name_vector(0x00000288, "v_atu83_osi8K", "atu83_osi8K");
  name_vector(0x0000028C, "v_atu83_osi8L", "atu83_osi8L");
  name_vector(0x00000290, "v_atu84_osi8M", "atu84_osi8M");
  name_vector(0x00000294, "v_atu84_osi8N", "atu84_osi8N");
  name_vector(0x00000298, "v_atu84_osi8O", "atu84_osi8O");
  name_vector(0x0000029C, "v_atu84_osi8P", "atu84_osi8P");
  name_vector(0x000002A0, "v_atu91_cmi9A", "atu91_cmi9A");
  name_vector(0x000002A4, "v_atu91_cmi9B", "atu91_cmi9B");
  name_vector(0x000002A8, "v_atu91_cmi9C", "atu91_cmi9C");
  name_vector(0x000002AC, "v_atu91_cmi9D", "atu91_cmi9D");
  name_vector(0x000002B0, "v_atu92_cmi9E", "atu92_cmi9E");
  name_vector(0x000002B8, "v_atu92_cmi9F", "atu92_cmi9F");
  name_vector(0x000002C0, "v_atu101_cmi10A", "atu101_cmi10A");
  name_vector(0x000002C8, "v_atu101_cmi10B", "atu101_cmi10B");
  name_vector(0x000002D0, "v_atu102_ici10A", "atu102_ici10A");
  name_vector(0x000002E0, "v_atu11_imi11A", "atu11_imi11A");
  name_vector(0x000002E8, "v_atu11_imi11B", "atu11_imi11B");
  name_vector(0x000002EC, "v_atu11_ovi11", "atu11_ovi11");
  name_vector(0x000002F0, "v_cmti0", "cmti0");
  name_vector(0x000002F8, "v_adi0", "adi0");
  name_vector(0x00000300, "v_cmti1", "cmti1");
  name_vector(0x00000308, "v_adi1", "adi1");
  name_vector(0x00000320, "v_sci0_eri0", "sci0_eri0");
  name_vector(0x00000324, "v_sci0_rxi0", "sci0_rxi0");
  name_vector(0x00000328, "v_sci0_txi0", "sci0_txi0");
  name_vector(0x0000032C, "v_sci0_tei0", "sci0_tei0");
  name_vector(0x00000330, "v_sci1_eri1", "sci1_eri1");
  name_vector(0x00000334, "v_sci1_rxi1", "sci1_rxi1");
  name_vector(0x00000338, "v_sci1_txi1", "sci1_txi1");
  name_vector(0x0000033C, "v_sci1_tei1", "sci1_tei1");
  name_vector(0x00000340, "v_sci2_eri2", "sci2_eri2");
  name_vector(0x00000344, "v_sci2_rxi2", "sci2_rxi2");
  name_vector(0x00000348, "v_sci2_txi2", "sci2_txi2");
  name_vector(0x0000034C, "v_sci2_tei2", "sci2_tei2");
  name_vector(0x00000350, "v_sci3_eri3", "sci3_eri3");
  name_vector(0x00000354, "v_sci3_rxi3", "sci3_rxi3");
  name_vector(0x00000358, "v_sci3_txi3", "sci3_txi3");
  name_vector(0x0000035C, "v_sci3_tei3", "sci3_tei3");
  name_vector(0x00000360, "v_sci4_eri4", "sci4_eri4");
  name_vector(0x00000364, "v_sci4_rxi4", "sci4_rxi4");
  name_vector(0x00000368, "v_sci4_txi4", "sci4_txi4");
  name_vector(0x0000036C, "v_sci4_tei4", "sci4_tei4");
  name_vector(0x00000370, "v_hcan_ers", "hcan_ers");
  name_vector(0x00000374, "v_hcan_ovr", "hcan_ovr");
  name_vector(0x00000378, "v_hcan_rm", "hcan_rm");
  name_vector(0x0000037C, "v_hcan_sle", "hcan_sle");
  name_vector(0x00000380, "v_wdt_iti", "wdt_iti");
  Message("done.\n");
}

static hardware_registers() {
  Message("Defining registers...");

  MakeByte(0xFFFFE400);
  MakeName(0xFFFFE400, "reg_MCR");

  MakeByte(0xFFFFE401);
  MakeName(0xFFFFE401, "reg_GSR");

  MakeWord(0xFFFFE402);
  MakeName(0xFFFFE402, "reg_BCR");

  MakeWord(0xFFFFE404);
  MakeName(0xFFFFE404, "reg_MBCR");

  MakeWord(0xFFFFE406);
  MakeName(0xFFFFE406, "reg_TXPR");

  MakeWord(0xFFFFE408);
  MakeName(0xFFFFE408, "reg_TXCR");

  MakeWord(0xFFFFE40A);
  MakeName(0xFFFFE40A, "reg_TXACK");

  MakeWord(0xFFFFE40C);
  MakeName(0xFFFFE40C, "reg_ABACK");

  MakeWord(0xFFFFE40E);
  MakeName(0xFFFFE40E, "reg_RXPR");

  MakeWord(0xFFFFE410);
  MakeName(0xFFFFE410, "reg_RFPR");

  MakeWord(0xFFFFE412);
  MakeName(0xFFFFE412, "reg_IRR");

  MakeWord(0xFFFFE414);
  MakeName(0xFFFFE414, "reg_MBIMR");

  MakeWord(0xFFFFE416);
  MakeName(0xFFFFE416, "reg_IMR");

  MakeByte(0xFFFFE418);
  MakeName(0xFFFFE418, "reg_REC");

  MakeByte(0xFFFFE419);
  MakeName(0xFFFFE419, "reg_TEC");

  MakeWord(0xFFFFE41A);
  MakeName(0xFFFFE41A, "reg_UMSR");

  MakeWord(0xFFFFE41C);
  MakeName(0xFFFFE41C, "reg_LAFML");

  MakeWord(0xFFFFE41E);
  MakeName(0xFFFFE41E, "reg_LAFMH");

  MakeByte(0xFFFFE420);
  MakeName(0xFFFFE420, "reg_MC0_1");

  MakeByte(0xFFFFE421);
  MakeName(0xFFFFE421, "reg_MC0_2");

  MakeByte(0xFFFFE422);
  MakeName(0xFFFFE422, "reg_MC0_3");

  MakeByte(0xFFFFE423);
  MakeName(0xFFFFE423, "reg_MC0_4");

  MakeByte(0xFFFFE424);
  MakeName(0xFFFFE424, "reg_MC0_5");

  MakeByte(0xFFFFE425);
  MakeName(0xFFFFE425, "reg_MC0_6");

  MakeByte(0xFFFFE426);
  MakeName(0xFFFFE426, "reg_MC0_7");

  MakeByte(0xFFFFE427);
  MakeName(0xFFFFE427, "reg_MC0_8");

  MakeByte(0xFFFFE428);
  MakeName(0xFFFFE428, "reg_MC1_1");

  MakeByte(0xFFFFE429);
  MakeName(0xFFFFE429, "reg_MC1_2");

  MakeByte(0xFFFFE42A);
  MakeName(0xFFFFE42A, "reg_MC1_3");

  MakeByte(0xFFFFE42B);
  MakeName(0xFFFFE42B, "reg_MC1_4");

  MakeByte(0xFFFFE42C);
  MakeName(0xFFFFE42C, "reg_MC1_5");

  MakeByte(0xFFFFE42D);
  MakeName(0xFFFFE42D, "reg_MC1_6");

  MakeByte(0xFFFFE42E);
  MakeName(0xFFFFE42E, "reg_MC1_7");

  MakeByte(0xFFFFE42F);
  MakeName(0xFFFFE42F, "reg_MC1_8");

  MakeByte(0xFFFFE430);
  MakeName(0xFFFFE430, "reg_MC2_1");

  MakeByte(0xFFFFE431);
  MakeName(0xFFFFE431, "reg_MC2_2");

  MakeByte(0xFFFFE432);
  MakeName(0xFFFFE432, "reg_MC2_3");

  MakeByte(0xFFFFE433);
  MakeName(0xFFFFE433, "reg_MC2_4");

  MakeByte(0xFFFFE434);
  MakeName(0xFFFFE434, "reg_MC2_5");

  MakeByte(0xFFFFE435);
  MakeName(0xFFFFE435, "reg_MC2_6");

  MakeByte(0xFFFFE436);
  MakeName(0xFFFFE436, "reg_MC2_7");

  MakeByte(0xFFFFE437);
  MakeName(0xFFFFE437, "reg_MC2_8");

  MakeByte(0xFFFFE438);
  MakeName(0xFFFFE438, "reg_MC3_1");

  MakeByte(0xFFFFE439);
  MakeName(0xFFFFE439, "reg_MC3_2");

  MakeByte(0xFFFFE43A);
  MakeName(0xFFFFE43A, "reg_MC3_3");

  MakeByte(0xFFFFE43B);
  MakeName(0xFFFFE43B, "reg_MC3_4");

  MakeByte(0xFFFFE43C);
  MakeName(0xFFFFE43C, "reg_MC3_5");

  MakeByte(0xFFFFE43D);
  MakeName(0xFFFFE43D, "reg_MC3_6");

  MakeByte(0xFFFFE43E);
  MakeName(0xFFFFE43E, "reg_MC3_7");

  MakeByte(0xFFFFE43F);
  MakeName(0xFFFFE43F, "reg_MC3_8");

  MakeByte(0xFFFFE440);
  MakeName(0xFFFFE440, "reg_MC4_1");

  MakeByte(0xFFFFE441);
  MakeName(0xFFFFE441, "reg_MC4_2");

  MakeByte(0xFFFFE442);
  MakeName(0xFFFFE442, "reg_MC4_3");

  MakeByte(0xFFFFE443);
  MakeName(0xFFFFE443, "reg_MC4_4");

  MakeByte(0xFFFFE444);
  MakeName(0xFFFFE444, "reg_MC4_5");

  MakeByte(0xFFFFE445);
  MakeName(0xFFFFE445, "reg_MC4_6");

  MakeByte(0xFFFFE446);
  MakeName(0xFFFFE446, "reg_MC4_7");

  MakeByte(0xFFFFE447);
  MakeName(0xFFFFE447, "reg_MC4_8");

  MakeByte(0xFFFFE448);
  MakeName(0xFFFFE448, "reg_MC5_1");

  MakeByte(0xFFFFE449);
  MakeName(0xFFFFE449, "reg_MC5_2");

  MakeByte(0xFFFFE44A);
  MakeName(0xFFFFE44A, "reg_MC5_3");

  MakeByte(0xFFFFE44B);
  MakeName(0xFFFFE44B, "reg_MC5_4");

  MakeByte(0xFFFFE44C);
  MakeName(0xFFFFE44C, "reg_MC5_5");

  MakeByte(0xFFFFE44D);
  MakeName(0xFFFFE44D, "reg_MC5_6");

  MakeByte(0xFFFFE44E);
  MakeName(0xFFFFE44E, "reg_MC5_7");

  MakeByte(0xFFFFE44F);
  MakeName(0xFFFFE44F, "reg_MC5_8");

  MakeByte(0xFFFFE450);
  MakeName(0xFFFFE450, "reg_MC6_1");

  MakeByte(0xFFFFE451);
  MakeName(0xFFFFE451, "reg_MC6_2");

  MakeByte(0xFFFFE452);
  MakeName(0xFFFFE452, "reg_MC6_3");

  MakeByte(0xFFFFE453);
  MakeName(0xFFFFE453, "reg_MC6_4");

  MakeByte(0xFFFFE454);
  MakeName(0xFFFFE454, "reg_MC6_5");

  MakeByte(0xFFFFE455);
  MakeName(0xFFFFE455, "reg_MC6_6");

  MakeByte(0xFFFFE456);
  MakeName(0xFFFFE456, "reg_MC6_7");

  MakeByte(0xFFFFE457);
  MakeName(0xFFFFE457, "reg_MC6_8");

  MakeByte(0xFFFFE458);
  MakeName(0xFFFFE458, "reg_MC7_1");

  MakeByte(0xFFFFE459);
  MakeName(0xFFFFE459, "reg_MC7_2");

  MakeByte(0xFFFFE45A);
  MakeName(0xFFFFE45A, "reg_MC7_3");

  MakeByte(0xFFFFE45B);
  MakeName(0xFFFFE45B, "reg_MC7_4");

  MakeByte(0xFFFFE45C);
  MakeName(0xFFFFE45C, "reg_MC7_5");

  MakeByte(0xFFFFE45D);
  MakeName(0xFFFFE45D, "reg_MC7_6");

  MakeByte(0xFFFFE45E);
  MakeName(0xFFFFE45E, "reg_MC7_7");

  MakeByte(0xFFFFE45F);
  MakeName(0xFFFFE45F, "reg_MC7_8");

  MakeByte(0xFFFFE460);
  MakeName(0xFFFFE460, "reg_MC8_1");

  MakeByte(0xFFFFE461);
  MakeName(0xFFFFE461, "reg_MC8_2");

  MakeByte(0xFFFFE462);
  MakeName(0xFFFFE462, "reg_MC8_3");

  MakeByte(0xFFFFE463);
  MakeName(0xFFFFE463, "reg_MC8_4");

  MakeByte(0xFFFFE464);
  MakeName(0xFFFFE464, "reg_MC8_5");

  MakeByte(0xFFFFE465);
  MakeName(0xFFFFE465, "reg_MC8_6");

  MakeByte(0xFFFFE466);
  MakeName(0xFFFFE466, "reg_MC8_7");

  MakeByte(0xFFFFE467);
  MakeName(0xFFFFE467, "reg_MC8_8");

  MakeByte(0xFFFFE468);
  MakeName(0xFFFFE468, "reg_MC9_1");

  MakeByte(0xFFFFE469);
  MakeName(0xFFFFE469, "reg_MC9_2");

  MakeByte(0xFFFFE46A);
  MakeName(0xFFFFE46A, "reg_MC9_3");

  MakeByte(0xFFFFE46B);
  MakeName(0xFFFFE46B, "reg_MC9_4");

  MakeByte(0xFFFFE46C);
  MakeName(0xFFFFE46C, "reg_MC9_5");

  MakeByte(0xFFFFE46D);
  MakeName(0xFFFFE46D, "reg_MC9_6");

  MakeByte(0xFFFFE46E);
  MakeName(0xFFFFE46E, "reg_MC9_7");

  MakeByte(0xFFFFE46F);
  MakeName(0xFFFFE46F, "reg_MC9_8");

  MakeByte(0xFFFFE470);
  MakeName(0xFFFFE470, "reg_MC10_1");

  MakeByte(0xFFFFE471);
  MakeName(0xFFFFE471, "reg_MC10_2");

  MakeByte(0xFFFFE472);
  MakeName(0xFFFFE472, "reg_MC10_3");

  MakeByte(0xFFFFE473);
  MakeName(0xFFFFE473, "reg_MC10_4");

  MakeByte(0xFFFFE474);
  MakeName(0xFFFFE474, "reg_MC10_5");

  MakeByte(0xFFFFE475);
  MakeName(0xFFFFE475, "reg_MC10_6");

  MakeByte(0xFFFFE476);
  MakeName(0xFFFFE476, "reg_MC10_7");

  MakeByte(0xFFFFE477);
  MakeName(0xFFFFE477, "reg_MC10_8");

  MakeByte(0xFFFFE478);
  MakeName(0xFFFFE478, "reg_MC11_1");

  MakeByte(0xFFFFE479);
  MakeName(0xFFFFE479, "reg_MC11_2");

  MakeByte(0xFFFFE47A);
  MakeName(0xFFFFE47A, "reg_MC11_3");

  MakeByte(0xFFFFE47B);
  MakeName(0xFFFFE47B, "reg_MC11_4");

  MakeByte(0xFFFFE47C);
  MakeName(0xFFFFE47C, "reg_MC11_5");

  MakeByte(0xFFFFE47D);
  MakeName(0xFFFFE47D, "reg_MC11_6");

  MakeByte(0xFFFFE47E);
  MakeName(0xFFFFE47E, "reg_MC11_7");

  MakeByte(0xFFFFE47F);
  MakeName(0xFFFFE47F, "reg_MC11_8");

  MakeByte(0xFFFFE480);
  MakeName(0xFFFFE480, "reg_MC12_1");

  MakeByte(0xFFFFE481);
  MakeName(0xFFFFE481, "reg_MC12_2");

  MakeByte(0xFFFFE482);
  MakeName(0xFFFFE482, "reg_MC12_3");

  MakeByte(0xFFFFE483);
  MakeName(0xFFFFE483, "reg_MC12_4");

  MakeByte(0xFFFFE484);
  MakeName(0xFFFFE484, "reg_MC12_5");

  MakeByte(0xFFFFE485);
  MakeName(0xFFFFE485, "reg_MC12_6");

  MakeByte(0xFFFFE486);
  MakeName(0xFFFFE486, "reg_MC12_7");

  MakeByte(0xFFFFE487);
  MakeName(0xFFFFE487, "reg_MC12_8");

  MakeByte(0xFFFFE488);
  MakeName(0xFFFFE488, "reg_MC13_1");

  MakeByte(0xFFFFE489);
  MakeName(0xFFFFE489, "reg_MC13_2");

  MakeByte(0xFFFFE48A);
  MakeName(0xFFFFE48A, "reg_MC13_3");

  MakeByte(0xFFFFE48B);
  MakeName(0xFFFFE48B, "reg_MC13_4");

  MakeByte(0xFFFFE48C);
  MakeName(0xFFFFE48C, "reg_MC13_5");

  MakeByte(0xFFFFE48D);
  MakeName(0xFFFFE48D, "reg_MC13_6");

  MakeByte(0xFFFFE48E);
  MakeName(0xFFFFE48E, "reg_MC13_7");

  MakeByte(0xFFFFE48F);
  MakeName(0xFFFFE48F, "reg_MC13_8");

  MakeByte(0xFFFFE490);
  MakeName(0xFFFFE490, "reg_MC14_1");

  MakeByte(0xFFFFE491);
  MakeName(0xFFFFE491, "reg_MC14_2");

  MakeByte(0xFFFFE492);
  MakeName(0xFFFFE492, "reg_MC14_3");

  MakeByte(0xFFFFE493);
  MakeName(0xFFFFE493, "reg_MC14_4");

  MakeByte(0xFFFFE494);
  MakeName(0xFFFFE494, "reg_MC14_5");

  MakeByte(0xFFFFE495);
  MakeName(0xFFFFE495, "reg_MC14_6");

  MakeByte(0xFFFFE496);
  MakeName(0xFFFFE496, "reg_MC14_7");

  MakeByte(0xFFFFE497);
  MakeName(0xFFFFE497, "reg_MC14_8");

  MakeByte(0xFFFFE498);
  MakeName(0xFFFFE498, "reg_MC15_1");

  MakeByte(0xFFFFE499);
  MakeName(0xFFFFE499, "reg_MC15_2");

  MakeByte(0xFFFFE49A);
  MakeName(0xFFFFE49A, "reg_MC15_3");

  MakeByte(0xFFFFE49B);
  MakeName(0xFFFFE49B, "reg_MC15_4");

  MakeByte(0xFFFFE49C);
  MakeName(0xFFFFE49C, "reg_MC15_5");

  MakeByte(0xFFFFE49D);
  MakeName(0xFFFFE49D, "reg_MC15_6");

  MakeByte(0xFFFFE49E);
  MakeName(0xFFFFE49E, "reg_MC15_7");

  MakeByte(0xFFFFE49F);
  MakeName(0xFFFFE49F, "reg_MC15_8");

  MakeByte(0xFFFFE4B0);
  MakeName(0xFFFFE4B0, "reg_MD0_1");

  MakeByte(0xFFFFE4B1);
  MakeName(0xFFFFE4B1, "reg_MD0_2");

  MakeByte(0xFFFFE4B2);
  MakeName(0xFFFFE4B2, "reg_MD0_3");

  MakeByte(0xFFFFE4B3);
  MakeName(0xFFFFE4B3, "reg_MD0_4");

  MakeByte(0xFFFFE4B4);
  MakeName(0xFFFFE4B4, "reg_MD0_5");

  MakeByte(0xFFFFE4B5);
  MakeName(0xFFFFE4B5, "reg_MD0_6");

  MakeByte(0xFFFFE4B6);
  MakeName(0xFFFFE4B6, "reg_MD0_7");

  MakeByte(0xFFFFE4B7);
  MakeName(0xFFFFE4B7, "reg_MD0_8");

  MakeByte(0xFFFFE4B8);
  MakeName(0xFFFFE4B8, "reg_MD1_1");

  MakeByte(0xFFFFE4B9);
  MakeName(0xFFFFE4B9, "reg_MD1_2");

  MakeByte(0xFFFFE4BA);
  MakeName(0xFFFFE4BA, "reg_MD1_3");

  MakeByte(0xFFFFE4BB);
  MakeName(0xFFFFE4BB, "reg_MD1_4");

  MakeByte(0xFFFFE4BC);
  MakeName(0xFFFFE4BC, "reg_MD1_5");

  MakeByte(0xFFFFE4BD);
  MakeName(0xFFFFE4BD, "reg_MD1_6");

  MakeByte(0xFFFFE4BE);
  MakeName(0xFFFFE4BE, "reg_MD1_7");

  MakeByte(0xFFFFE4BF);
  MakeName(0xFFFFE4BF, "reg_MD1_8");

  MakeByte(0xFFFFE4C0);
  MakeName(0xFFFFE4C0, "reg_MD2_1");

  MakeByte(0xFFFFE4C1);
  MakeName(0xFFFFE4C1, "reg_MD2_2");

  MakeByte(0xFFFFE4C2);
  MakeName(0xFFFFE4C2, "reg_MD2_3");

  MakeByte(0xFFFFE4C3);
  MakeName(0xFFFFE4C3, "reg_MD2_4");

  MakeByte(0xFFFFE4C4);
  MakeName(0xFFFFE4C4, "reg_MD2_5");

  MakeByte(0xFFFFE4C5);
  MakeName(0xFFFFE4C5, "reg_MD2_6");

  MakeByte(0xFFFFE4C6);
  MakeName(0xFFFFE4C6, "reg_MD2_7");

  MakeByte(0xFFFFE4C7);
  MakeName(0xFFFFE4C7, "reg_MD2_8");

  MakeByte(0xFFFFE4C8);
  MakeName(0xFFFFE4C8, "reg_MD3_1");

  MakeByte(0xFFFFE4C9);
  MakeName(0xFFFFE4C9, "reg_MD3_2");

  MakeByte(0xFFFFE4CA);
  MakeName(0xFFFFE4CA, "reg_MD3_3");

  MakeByte(0xFFFFE4CB);
  MakeName(0xFFFFE4CB, "reg_MD3_4");

  MakeByte(0xFFFFE4CC);
  MakeName(0xFFFFE4CC, "reg_MD3_5");

  MakeByte(0xFFFFE4CD);
  MakeName(0xFFFFE4CD, "reg_MD3_6");

  MakeByte(0xFFFFE4CE);
  MakeName(0xFFFFE4CE, "reg_MD3_7");

  MakeByte(0xFFFFE4CF);
  MakeName(0xFFFFE4CF, "reg_MD3_8");

  MakeByte(0xFFFFE4D0);
  MakeName(0xFFFFE4D0, "reg_MD4_1");

  MakeByte(0xFFFFE4D1);
  MakeName(0xFFFFE4D1, "reg_MD4_2");

  MakeByte(0xFFFFE4D2);
  MakeName(0xFFFFE4D2, "reg_MD4_3");

  MakeByte(0xFFFFE4D3);
  MakeName(0xFFFFE4D3, "reg_MD4_4");

  MakeByte(0xFFFFE4D4);
  MakeName(0xFFFFE4D4, "reg_MD4_5");

  MakeByte(0xFFFFE4D5);
  MakeName(0xFFFFE4D5, "reg_MD4_6");

  MakeByte(0xFFFFE4D6);
  MakeName(0xFFFFE4D6, "reg_MD4_7");

  MakeByte(0xFFFFE4D7);
  MakeName(0xFFFFE4D7, "reg_MD4_8");

  MakeByte(0xFFFFE4D8);
  MakeName(0xFFFFE4D8, "reg_MD5_1");

  MakeByte(0xFFFFE4D9);
  MakeName(0xFFFFE4D9, "reg_MD5_2");

  MakeByte(0xFFFFE4DA);
  MakeName(0xFFFFE4DA, "reg_MD5_3");

  MakeByte(0xFFFFE4DB);
  MakeName(0xFFFFE4DB, "reg_MD5_4");

  MakeByte(0xFFFFE4DC);
  MakeName(0xFFFFE4DC, "reg_MD5_5");

  MakeByte(0xFFFFE4DD);
  MakeName(0xFFFFE4DD, "reg_MD5_6");

  MakeByte(0xFFFFE4DE);
  MakeName(0xFFFFE4DE, "reg_MD5_7");

  MakeByte(0xFFFFE4DF);
  MakeName(0xFFFFE4DF, "reg_MD5_8");

  MakeByte(0xFFFFE4E0);
  MakeName(0xFFFFE4E0, "reg_MD6_1");

  MakeByte(0xFFFFE4E1);
  MakeName(0xFFFFE4E1, "reg_MD6_2");

  MakeByte(0xFFFFE4E2);
  MakeName(0xFFFFE4E2, "reg_MD6_3");

  MakeByte(0xFFFFE4E3);
  MakeName(0xFFFFE4E3, "reg_MD6_4");

  MakeByte(0xFFFFE4E4);
  MakeName(0xFFFFE4E4, "reg_MD6_5");

  MakeByte(0xFFFFE4E5);
  MakeName(0xFFFFE4E5, "reg_MD6_6");

  MakeByte(0xFFFFE4E6);
  MakeName(0xFFFFE4E6, "reg_MD6_7");

  MakeByte(0xFFFFE4E7);
  MakeName(0xFFFFE4E7, "reg_MD6_8");

  MakeByte(0xFFFFE4E8);
  MakeName(0xFFFFE4E8, "reg_MD7_1");

  MakeByte(0xFFFFE4E9);
  MakeName(0xFFFFE4E9, "reg_MD7_2");

  MakeByte(0xFFFFE4EA);
  MakeName(0xFFFFE4EA, "reg_MD7_3");

  MakeByte(0xFFFFE4EB);
  MakeName(0xFFFFE4EB, "reg_MD7_4");

  MakeByte(0xFFFFE4EC);
  MakeName(0xFFFFE4EC, "reg_MD7_5");

  MakeByte(0xFFFFE4ED);
  MakeName(0xFFFFE4ED, "reg_MD7_6");

  MakeByte(0xFFFFE4EE);
  MakeName(0xFFFFE4EE, "reg_MD7_7");

  MakeByte(0xFFFFE4EF);
  MakeName(0xFFFFE4EF, "reg_MD7_8");

  MakeByte(0xFFFFE4F0);
  MakeName(0xFFFFE4F0, "reg_MD8_1");

  MakeByte(0xFFFFE4F1);
  MakeName(0xFFFFE4F1, "reg_MD8_2");

  MakeByte(0xFFFFE4F2);
  MakeName(0xFFFFE4F2, "reg_MD8_3");

  MakeByte(0xFFFFE4F3);
  MakeName(0xFFFFE4F3, "reg_MD8_4");

  MakeByte(0xFFFFE4F4);
  MakeName(0xFFFFE4F4, "reg_MD8_5");

  MakeByte(0xFFFFE4F5);
  MakeName(0xFFFFE4F5, "reg_MD8_6");

  MakeByte(0xFFFFE4F6);
  MakeName(0xFFFFE4F6, "reg_MD8_7");

  MakeByte(0xFFFFE4F7);
  MakeName(0xFFFFE4F7, "reg_MD8_8");

  MakeByte(0xFFFFE4F8);
  MakeName(0xFFFFE4F8, "reg_MD9_1");

  MakeByte(0xFFFFE4F9);
  MakeName(0xFFFFE4F9, "reg_MD9_2");

  MakeByte(0xFFFFE4FA);
  MakeName(0xFFFFE4FA, "reg_MD9_3");

  MakeByte(0xFFFFE4FB);
  MakeName(0xFFFFE4FB, "reg_MD9_4");

  MakeByte(0xFFFFE4FC);
  MakeName(0xFFFFE4FC, "reg_MD9_5");

  MakeByte(0xFFFFE4FD);
  MakeName(0xFFFFE4FD, "reg_MD9_6");

  MakeByte(0xFFFFE4FE);
  MakeName(0xFFFFE4FE, "reg_MD9_7");

  MakeByte(0xFFFFE4FF);
  MakeName(0xFFFFE4FF, "reg_MD9_8");

  MakeByte(0xFFFFE500);
  MakeName(0xFFFFE500, "reg_MD10_1");

  MakeByte(0xFFFFE501);
  MakeName(0xFFFFE501, "reg_MD10_2");

  MakeByte(0xFFFFE502);
  MakeName(0xFFFFE502, "reg_MD10_3");

  MakeByte(0xFFFFE503);
  MakeName(0xFFFFE503, "reg_MD10_4");

  MakeByte(0xFFFFE504);
  MakeName(0xFFFFE504, "reg_MD10_5");

  MakeByte(0xFFFFE505);
  MakeName(0xFFFFE505, "reg_MD10_6");

  MakeByte(0xFFFFE506);
  MakeName(0xFFFFE506, "reg_MD10_7");

  MakeByte(0xFFFFE507);
  MakeName(0xFFFFE507, "reg_MD10_8");

  MakeByte(0xFFFFE508);
  MakeName(0xFFFFE508, "reg_MD11_1");

  MakeByte(0xFFFFE509);
  MakeName(0xFFFFE509, "reg_MD11_2");

  MakeByte(0xFFFFE50A);
  MakeName(0xFFFFE50A, "reg_MD11_3");

  MakeByte(0xFFFFE50B);
  MakeName(0xFFFFE50B, "reg_MD11_4");

  MakeByte(0xFFFFE50C);
  MakeName(0xFFFFE50C, "reg_MD11_5");

  MakeByte(0xFFFFE50D);
  MakeName(0xFFFFE50D, "reg_MD11_6");

  MakeByte(0xFFFFE50E);
  MakeName(0xFFFFE50E, "reg_MD11_7");

  MakeByte(0xFFFFE50F);
  MakeName(0xFFFFE50F, "reg_MD11_8");

  MakeByte(0xFFFFE510);
  MakeName(0xFFFFE510, "reg_MD12_1");

  MakeByte(0xFFFFE511);
  MakeName(0xFFFFE511, "reg_MD12_2");

  MakeByte(0xFFFFE512);
  MakeName(0xFFFFE512, "reg_MD12_3");

  MakeByte(0xFFFFE513);
  MakeName(0xFFFFE513, "reg_MD12_4");

  MakeByte(0xFFFFE514);
  MakeName(0xFFFFE514, "reg_MD12_5");

  MakeByte(0xFFFFE515);
  MakeName(0xFFFFE515, "reg_MD12_6");

  MakeByte(0xFFFFE516);
  MakeName(0xFFFFE516, "reg_MD12_7");

  MakeByte(0xFFFFE517);
  MakeName(0xFFFFE517, "reg_MD12_8");

  MakeByte(0xFFFFE518);
  MakeName(0xFFFFE518, "reg_MD13_1");

  MakeByte(0xFFFFE519);
  MakeName(0xFFFFE519, "reg_MD13_2");

  MakeByte(0xFFFFE51A);
  MakeName(0xFFFFE51A, "reg_MD13_3");

  MakeByte(0xFFFFE51B);
  MakeName(0xFFFFE51B, "reg_MD13_4");

  MakeByte(0xFFFFE51C);
  MakeName(0xFFFFE51C, "reg_MD13_5");

  MakeByte(0xFFFFE51D);
  MakeName(0xFFFFE51D, "reg_MD13_6");

  MakeByte(0xFFFFE51E);
  MakeName(0xFFFFE51E, "reg_MD13_7");

  MakeByte(0xFFFFE51F);
  MakeName(0xFFFFE51F, "reg_MD13_8");

  MakeByte(0xFFFFE520);
  MakeName(0xFFFFE520, "reg_MD14_1");

  MakeByte(0xFFFFE521);
  MakeName(0xFFFFE521, "reg_MD14_2");

  MakeByte(0xFFFFE522);
  MakeName(0xFFFFE522, "reg_MD14_3");

  MakeByte(0xFFFFE523);
  MakeName(0xFFFFE523, "reg_MD14_4");

  MakeByte(0xFFFFE524);
  MakeName(0xFFFFE524, "reg_MD14_5");

  MakeByte(0xFFFFE525);
  MakeName(0xFFFFE525, "reg_MD14_6");

  MakeByte(0xFFFFE526);
  MakeName(0xFFFFE526, "reg_MD14_7");

  MakeByte(0xFFFFE527);
  MakeName(0xFFFFE527, "reg_MD14_8");

  MakeByte(0xFFFFE528);
  MakeName(0xFFFFE528, "reg_MD15_1");

  MakeByte(0xFFFFE529);
  MakeName(0xFFFFE529, "reg_MD15_2");

  MakeByte(0xFFFFE52A);
  MakeName(0xFFFFE52A, "reg_MD15_3");

  MakeByte(0xFFFFE52B);
  MakeName(0xFFFFE52B, "reg_MD15_4");

  MakeByte(0xFFFFE52C);
  MakeName(0xFFFFE52C, "reg_MD15_5");

  MakeByte(0xFFFFE52D);
  MakeName(0xFFFFE52D, "reg_MD15_6");

  MakeByte(0xFFFFE52E);
  MakeName(0xFFFFE52E, "reg_MD15_7");

  MakeByte(0xFFFFE52F);
  MakeName(0xFFFFE52F, "reg_MD15_8");

  MakeByte(0xFFFFE800);
  MakeName(0xFFFFE800, "reg_FLMCR1");

  MakeByte(0xFFFFE801);
  MakeName(0xFFFFE801, "reg_FLMCR2");

  MakeByte(0xFFFFE802);
  MakeName(0xFFFFE802, "reg_EBR1");

  MakeByte(0xFFFFE803);
  MakeName(0xFFFFE803, "reg_EBR2");

  MakeWord(0xFFFFEC00);
  MakeName(0xFFFFEC00, "reg_UBARH");

  MakeWord(0xFFFFEC02);
  MakeName(0xFFFFEC02, "reg_UBARL");

  MakeWord(0xFFFFEC04);
  MakeName(0xFFFFEC04, "reg_UBAMRH");

  MakeWord(0xFFFFEC06);
  MakeName(0xFFFFEC06, "reg_UBAMRL");

  MakeWord(0xFFFFEC08);
  MakeName(0xFFFFEC08, "reg_UBBR");

  MakeWord(0xFFFFEC0A);
  MakeName(0xFFFFEC0A, "reg_UBCR");

  MakeByte(0xFFFFEC10);
  MakeName(0xFFFFEC10, "reg_TCSR");

  MakeByte(0xFFFFEC11);
  MakeName(0xFFFFEC11, "reg_TCNT");

  MakeByte(0xFFFFEC12);
  MakeName(0xFFFFEC12, "reg_RSTCSR_wr");

  MakeByte(0xFFFFEC13);
  MakeName(0xFFFFEC13, "reg_RSTCSR_rd");

  MakeByte(0xFFFFEC14);
  MakeName(0xFFFFEC14, "reg_SBYCR");

  MakeWord(0xFFFFEC20);
  MakeName(0xFFFFEC20, "reg_BCR1");

  MakeWord(0xFFFFEC22);
  MakeName(0xFFFFEC22, "reg_BCR2");

  MakeWord(0xFFFFEC24);
  MakeName(0xFFFFEC24, "reg_WCR");

  MakeWord(0xFFFFEC26);
  MakeName(0xFFFFEC26, "reg_RAMER");

  MakeWord(0xFFFFECB0);
  MakeName(0xFFFFECB0, "reg_DMAOR");

  MakeDword(0xFFFFECC0);
  MakeName(0xFFFFECC0, "reg_SAR0");

  MakeDword(0xFFFFECC4);
  MakeName(0xFFFFECC4, "reg_DAR0");

  MakeDword(0xFFFFECC8);
  MakeName(0xFFFFECC8, "reg_DMATCR0");

  MakeDword(0xFFFFECCC);
  MakeName(0xFFFFECCC, "reg_CHCR0");

  MakeDword(0xFFFFECD0);
  MakeName(0xFFFFECD0, "reg_SAR1");

  MakeDword(0xFFFFECD4);
  MakeName(0xFFFFECD4, "reg_DAR1");

  MakeDword(0xFFFFECD8);
  MakeName(0xFFFFECD8, "reg_DMATCR1");

  MakeDword(0xFFFFECDC);
  MakeName(0xFFFFECDC, "reg_CHCR1");

  MakeDword(0xFFFFECE0);
  MakeName(0xFFFFECE0, "reg_SAR2");

  MakeDword(0xFFFFECE4);
  MakeName(0xFFFFECE4, "reg_DAR2");

  MakeDword(0xFFFFECE8);
  MakeName(0xFFFFECE8, "reg_DMATCR2");

  MakeDword(0xFFFFECEC);
  MakeName(0xFFFFECEC, "reg_CHCR2");

  MakeDword(0xFFFFECF0);
  MakeName(0xFFFFECF0, "reg_SAR3");

  MakeDword(0xFFFFECF4);
  MakeName(0xFFFFECF4, "reg_DAR3");

  MakeDword(0xFFFFECF8);
  MakeName(0xFFFFECF8, "reg_DMATCR3");

  MakeDword(0xFFFFECFC);
  MakeName(0xFFFFECFC, "reg_CHCR3");

  MakeWord(0xFFFFED00);
  MakeName(0xFFFFED00, "reg_IPRA");

  MakeWord(0xFFFFED04);
  MakeName(0xFFFFED04, "reg_IPRC");

  MakeWord(0xFFFFED06);
  MakeName(0xFFFFED06, "reg_IPRD");

  MakeWord(0xFFFFED08);
  MakeName(0xFFFFED08, "reg_IPRE");

  MakeWord(0xFFFFED0A);
  MakeName(0xFFFFED0A, "reg_IPRF");

  MakeWord(0xFFFFED0C);
  MakeName(0xFFFFED0C, "reg_IPRG");

  MakeWord(0xFFFFED0E);
  MakeName(0xFFFFED0E, "reg_IPRH");

  MakeWord(0xFFFFED10);
  MakeName(0xFFFFED10, "reg_IPRI");

  MakeWord(0xFFFFED12);
  MakeName(0xFFFFED12, "reg_IPRJ");

  MakeWord(0xFFFFED14);
  MakeName(0xFFFFED14, "reg_IPRK");

  MakeWord(0xFFFFED16);
  MakeName(0xFFFFED16, "reg_IPRL");

  MakeWord(0xFFFFED18);
  MakeName(0xFFFFED18, "reg_ICR");

  MakeWord(0xFFFFED1A);
  MakeName(0xFFFFED1A, "reg_ISR");

  MakeByte(0xFFFFF000);
  MakeName(0xFFFFF000, "reg_SMR0");

  MakeByte(0xFFFFF001);
  MakeName(0xFFFFF001, "reg_BRR0");

  MakeByte(0xFFFFF002);
  MakeName(0xFFFFF002, "reg_SCR0");

  MakeByte(0xFFFFF003);
  MakeName(0xFFFFF003, "reg_TDR0");

  MakeByte(0xFFFFF004);
  MakeName(0xFFFFF004, "reg_SSR0");

  MakeByte(0xFFFFF005);
  MakeName(0xFFFFF005, "reg_RDR0");

  MakeByte(0xFFFFF006);
  MakeName(0xFFFFF006, "reg_SDCR0");

  MakeByte(0xFFFFF008);
  MakeName(0xFFFFF008, "reg_SMR1");

  MakeByte(0xFFFFF009);
  MakeName(0xFFFFF009, "reg_BRR1");

  MakeByte(0xFFFFF00A);
  MakeName(0xFFFFF00A, "reg_SCR1");

  MakeByte(0xFFFFF00B);
  MakeName(0xFFFFF00B, "reg_TDR1");

  MakeByte(0xFFFFF00C);
  MakeName(0xFFFFF00C, "reg_SSR1");

  MakeByte(0xFFFFF00D);
  MakeName(0xFFFFF00D, "reg_RDR1");

  MakeByte(0xFFFFF00E);
  MakeName(0xFFFFF00E, "reg_SDCR1");

  MakeByte(0xFFFFF010);
  MakeName(0xFFFFF010, "reg_SMR2");

  MakeByte(0xFFFFF011);
  MakeName(0xFFFFF011, "reg_BRR2");

  MakeByte(0xFFFFF012);
  MakeName(0xFFFFF012, "reg_SCR2");

  MakeByte(0xFFFFF013);
  MakeName(0xFFFFF013, "reg_TDR2");

  MakeByte(0xFFFFF014);
  MakeName(0xFFFFF014, "reg_SSR2");

  MakeByte(0xFFFFF015);
  MakeName(0xFFFFF015, "reg_RDR2");

  MakeByte(0xFFFFF016);
  MakeName(0xFFFFF016, "reg_SDCR2");

  MakeByte(0xFFFFF018);
  MakeName(0xFFFFF018, "reg_SMR3");

  MakeByte(0xFFFFF019);
  MakeName(0xFFFFF019, "reg_BRR3");

  MakeByte(0xFFFFF01A);
  MakeName(0xFFFFF01A, "reg_SCR3");

  MakeByte(0xFFFFF01B);
  MakeName(0xFFFFF01B, "reg_TDR3");

  MakeByte(0xFFFFF01C);
  MakeName(0xFFFFF01C, "reg_SSR3");

  MakeByte(0xFFFFF01D);
  MakeName(0xFFFFF01D, "reg_RDR3");

  MakeByte(0xFFFFF01E);
  MakeName(0xFFFFF01E, "reg_SDCR3");

  MakeByte(0xFFFFF020);
  MakeName(0xFFFFF020, "reg_SMR4");

  MakeByte(0xFFFFF021);
  MakeName(0xFFFFF021, "reg_BRR4");

  MakeByte(0xFFFFF022);
  MakeName(0xFFFFF022, "reg_SCR4");

  MakeByte(0xFFFFF023);
  MakeName(0xFFFFF023, "reg_TDR4");

  MakeByte(0xFFFFF024);
  MakeName(0xFFFFF024, "reg_SSR4");

  MakeByte(0xFFFFF025);
  MakeName(0xFFFFF025, "reg_RDR4");

  MakeByte(0xFFFFF026);
  MakeName(0xFFFFF026, "reg_SDCR4");

  MakeByte(0xFFFFF400);
  MakeName(0xFFFFF400, "reg_TSTR2");

  MakeByte(0xFFFFF401);
  MakeName(0xFFFFF401, "reg_TSTR1");

  MakeByte(0xFFFFF402);
  MakeName(0xFFFFF402, "reg_TSTR3");

  MakeByte(0xFFFFF404);
  MakeName(0xFFFFF404, "reg_PSCR1");

  MakeByte(0xFFFFF406);
  MakeName(0xFFFFF406, "reg_PSCR2");

  MakeByte(0xFFFFF408);
  MakeName(0xFFFFF408, "reg_PSCR3");

  MakeByte(0xFFFFF40A);
  MakeName(0xFFFFF40A, "reg_PSCR4");

  MakeWord(0xFFFFF420);
  MakeName(0xFFFFF420, "reg_ICR0DH");

  MakeWord(0xFFFFF422);
  MakeName(0xFFFFF422, "reg_ICR0DL");

  MakeWord(0xFFFFF424);
  MakeName(0xFFFFF424, "reg_ITVRR1");

  MakeByte(0xFFFFF426);
  MakeName(0xFFFFF426, "reg_ITVRR2A");

  MakeByte(0xFFFFF428);
  MakeName(0xFFFFF428, "reg_ITVRR2B");

  MakeByte(0xFFFFF42A);
  MakeName(0xFFFFF42A, "reg_TIOR0");

  MakeWord(0xFFFFF42C);
  MakeName(0xFFFFF42C, "reg_TSR0");

  MakeWord(0xFFFFF42E);
  MakeName(0xFFFFF42E, "reg_TIER0");

  MakeWord(0xFFFFF430);
  MakeName(0xFFFFF430, "reg_TCNT0H");

  MakeWord(0xFFFFF432);
  MakeName(0xFFFFF432, "reg_TCNT0L");

  MakeWord(0xFFFFF434);
  MakeName(0xFFFFF434, "reg_ICR0AH");

  MakeWord(0xFFFFF436);
  MakeName(0xFFFFF436, "reg_ICR0AL");

  MakeWord(0xFFFFF438);
  MakeName(0xFFFFF438, "reg_ICR0BH");

  MakeWord(0xFFFFF43A);
  MakeName(0xFFFFF43A, "reg_ICR0BL");

  MakeWord(0xFFFFF43C);
  MakeName(0xFFFFF43C, "reg_ICR0CH");

  MakeWord(0xFFFFF43E);
  MakeName(0xFFFFF43E, "reg_ICR0CL");

  MakeWord(0xFFFFF440);
  MakeName(0xFFFFF440, "reg_TCNT1A");

  MakeWord(0xFFFFF442);
  MakeName(0xFFFFF442, "reg_TCNT1B");

  MakeWord(0xFFFFF444);
  MakeName(0xFFFFF444, "reg_GR1A");

  MakeWord(0xFFFFF446);
  MakeName(0xFFFFF446, "reg_GR1B");

  MakeWord(0xFFFFF448);
  MakeName(0xFFFFF448, "reg_GR1C");

  MakeWord(0xFFFFF44A);
  MakeName(0xFFFFF44A, "reg_GR1D");

  MakeWord(0xFFFFF44C);
  MakeName(0xFFFFF44C, "reg_GR1E");

  MakeWord(0xFFFFF44E);
  MakeName(0xFFFFF44E, "reg_GR1F");

  MakeWord(0xFFFFF450);
  MakeName(0xFFFFF450, "reg_GR1G");

  MakeWord(0xFFFFF452);
  MakeName(0xFFFFF452, "reg_GR1H");

  MakeWord(0xFFFFF454);
  MakeName(0xFFFFF454, "reg_OCR1");

  MakeWord(0xFFFFF456);
  MakeName(0xFFFFF456, "reg_OSBR1");

  MakeByte(0xFFFFF458);
  MakeName(0xFFFFF458, "reg_TIOR1B");

  MakeByte(0xFFFFF459);
  MakeName(0xFFFFF459, "reg_TIOR1A");

  MakeByte(0xFFFFF45A);
  MakeName(0xFFFFF45A, "reg_TIOR1D");

  MakeByte(0xFFFFF45B);
  MakeName(0xFFFFF45B, "reg_TIOR1C");

  MakeByte(0xFFFFF45C);
  MakeName(0xFFFFF45C, "reg_TCR1B");

  MakeByte(0xFFFFF45D);
  MakeName(0xFFFFF45D, "reg_TCR1A");

  MakeByte(0xFFFFF45E);
  MakeName(0xFFFFF45E, "reg_TSR1A");

  MakeByte(0xFFFFF45F);
  MakeName(0xFFFFF45F, "reg_IMF1H");

  MakeWord(0xFFFFF460);
  MakeName(0xFFFFF460, "reg_TSR1B");

  MakeWord(0xFFFFF462);
  MakeName(0xFFFFF462, "reg_TIER1A");

  MakeWord(0xFFFFF464);
  MakeName(0xFFFFF464, "reg_TIER1B");

  MakeByte(0xFFFFF466);
  MakeName(0xFFFFF466, "reg_TRGMDR");

  MakeWord(0xFFFFF480);
  MakeName(0xFFFFF480, "reg_TSR3");

  MakeWord(0xFFFFF482);
  MakeName(0xFFFFF482, "reg_TIER3");

  MakeByte(0xFFFFF484);
  MakeName(0xFFFFF484, "reg_TMDR");

  MakeWord(0xFFFFF4A0);
  MakeName(0xFFFFF4A0, "reg_TCNT3");

  MakeWord(0xFFFFF4A2);
  MakeName(0xFFFFF4A2, "reg_GR3A");

  MakeWord(0xFFFFF4A4);
  MakeName(0xFFFFF4A4, "reg_GR3B");

  MakeWord(0xFFFFF4A6);
  MakeName(0xFFFFF4A6, "reg_GR3C");

  MakeWord(0xFFFFF4A8);
  MakeName(0xFFFFF4A8, "reg_GR3D");

  MakeByte(0xFFFFF4AA);
  MakeName(0xFFFFF4AA, "reg_TIOR3B");

  MakeByte(0xFFFFF4AB);
  MakeName(0xFFFFF4AB, "reg_TIOR3A");

  MakeByte(0xFFFFF4AC);
  MakeName(0xFFFFF4AC, "reg_TCR3");

  MakeWord(0xFFFFF4C0);
  MakeName(0xFFFFF4C0, "reg_TCNT4");

  MakeWord(0xFFFFF4C2);
  MakeName(0xFFFFF4C2, "reg_GR4A");

  MakeWord(0xFFFFF4C4);
  MakeName(0xFFFFF4C4, "reg_GR4B");

  MakeWord(0xFFFFF4C6);
  MakeName(0xFFFFF4C6, "reg_GR4C");

  MakeWord(0xFFFFF4C8);
  MakeName(0xFFFFF4C8, "reg_GR4D");

  MakeByte(0xFFFFF4CA);
  MakeName(0xFFFFF4CA, "reg_TIOR4B");

  MakeByte(0xFFFFF4CB);
  MakeName(0xFFFFF4CB, "reg_TIOR4A");

  MakeByte(0xFFFFF4CC);
  MakeName(0xFFFFF4CC, "reg_TCR4");

  MakeWord(0xFFFFF4E0);
  MakeName(0xFFFFF4E0, "reg_TCNT5");

  MakeWord(0xFFFFF4E2);
  MakeName(0xFFFFF4E2, "reg_GR5A");

  MakeWord(0xFFFFF4E4);
  MakeName(0xFFFFF4E4, "reg_GR5B");

  MakeWord(0xFFFFF4E6);
  MakeName(0xFFFFF4E6, "reg_GR5C");

  MakeWord(0xFFFFF4E8);
  MakeName(0xFFFFF4E8, "reg_GR5D");

  MakeByte(0xFFFFF4EA);
  MakeName(0xFFFFF4EA, "reg_TIOR5B");

  MakeByte(0xFFFFF4EB);
  MakeName(0xFFFFF4EB, "reg_TIOR5A");

  MakeByte(0xFFFFF4EC);
  MakeName(0xFFFFF4EC, "reg_TCR5");

  MakeWord(0xFFFFF500);
  MakeName(0xFFFFF500, "reg_TCNT6A");

  MakeWord(0xFFFFF502);
  MakeName(0xFFFFF502, "reg_TCNT6B");

  MakeWord(0xFFFFF504);
  MakeName(0xFFFFF504, "reg_TCNT6C");

  MakeWord(0xFFFFF506);
  MakeName(0xFFFFF506, "reg_TCNT6D");

  MakeWord(0xFFFFF508);
  MakeName(0xFFFFF508, "reg_CYLR6A");

  MakeWord(0xFFFFF50A);
  MakeName(0xFFFFF50A, "reg_CYLR6B");

  MakeWord(0xFFFFF50C);
  MakeName(0xFFFFF50C, "reg_CYLR6C");

  MakeWord(0xFFFFF50E);
  MakeName(0xFFFFF50E, "reg_CYLR6D");

  MakeWord(0xFFFFF510);
  MakeName(0xFFFFF510, "reg_BFR6A");

  MakeWord(0xFFFFF512);
  MakeName(0xFFFFF512, "reg_BFR6B");

  MakeWord(0xFFFFF514);
  MakeName(0xFFFFF514, "reg_BFR6C");

  MakeWord(0xFFFFF516);
  MakeName(0xFFFFF516, "reg_BFR6D");

  MakeWord(0xFFFFF518);
  MakeName(0xFFFFF518, "reg_DTR6A");

  MakeWord(0xFFFFF51A);
  MakeName(0xFFFFF51A, "reg_DTR6B");

  MakeWord(0xFFFFF51C);
  MakeName(0xFFFFF51C, "reg_DTR6C");

  MakeWord(0xFFFFF51E);
  MakeName(0xFFFFF51E, "reg_DTR6D");

  MakeByte(0xFFFFF520);
  MakeName(0xFFFFF520, "reg_TCR6B");

  MakeByte(0xFFFFF521);
  MakeName(0xFFFFF521, "reg_TCR6A");

  MakeWord(0xFFFFF522);
  MakeName(0xFFFFF522, "reg_TSR6");

  MakeWord(0xFFFFF524);
  MakeName(0xFFFFF524, "reg_TIER6");

  MakeByte(0xFFFFF526);
  MakeName(0xFFFFF526, "reg_PMDR");

  MakeWord(0xFFFFF580);
  MakeName(0xFFFFF580, "reg_TCNT7A");

  MakeWord(0xFFFFF582);
  MakeName(0xFFFFF582, "reg_TCNT7B");

  MakeWord(0xFFFFF584);
  MakeName(0xFFFFF584, "reg_TCNT7C");

  MakeWord(0xFFFFF586);
  MakeName(0xFFFFF586, "reg_TCNT7D");

  MakeWord(0xFFFFF588);
  MakeName(0xFFFFF588, "reg_CYLR7A");

  MakeWord(0xFFFFF58A);
  MakeName(0xFFFFF58A, "reg_CYLR7B");

  MakeWord(0xFFFFF58C);
  MakeName(0xFFFFF58C, "reg_CYLR7C");

  MakeWord(0xFFFFF58E);
  MakeName(0xFFFFF58E, "reg_CYLR7D");

  MakeWord(0xFFFFF590);
  MakeName(0xFFFFF590, "reg_BFR7A");

  MakeWord(0xFFFFF592);
  MakeName(0xFFFFF592, "reg_BFR7B");

  MakeWord(0xFFFFF594);
  MakeName(0xFFFFF594, "reg_BFR7C");

  MakeWord(0xFFFFF596);
  MakeName(0xFFFFF596, "reg_BFR7D");

  MakeWord(0xFFFFF598);
  MakeName(0xFFFFF598, "reg_DTR7A");

  MakeWord(0xFFFFF59A);
  MakeName(0xFFFFF59A, "reg_DTR7B");

  MakeWord(0xFFFFF59C);
  MakeName(0xFFFFF59C, "reg_DTR7C");

  MakeWord(0xFFFFF59E);
  MakeName(0xFFFFF59E, "reg_DTR7D");

  MakeByte(0xFFFFF5A0);
  MakeName(0xFFFFF5A0, "reg_TCR7B");

  MakeByte(0xFFFFF5A1);
  MakeName(0xFFFFF5A1, "reg_TCR7A");

  MakeWord(0xFFFFF5A2);
  MakeName(0xFFFFF5A2, "reg_TSR7");

  MakeWord(0xFFFFF5A4);
  MakeName(0xFFFFF5A4, "reg_TIER7");

  MakeWord(0xFFFFF5C0);
  MakeName(0xFFFFF5C0, "reg_TCNT11");

  MakeWord(0xFFFFF5C2);
  MakeName(0xFFFFF5C2, "reg_GR11A");

  MakeWord(0xFFFFF5C4);
  MakeName(0xFFFFF5C4, "reg_GR11B");

  MakeByte(0xFFFFF5C6);
  MakeName(0xFFFFF5C6, "reg_TIOR11");

  MakeByte(0xFFFFF5C8);
  MakeName(0xFFFFF5C8, "reg_TCR11");

  MakeWord(0xFFFFF5CA);
  MakeName(0xFFFFF5CA, "reg_TSR11");

  MakeWord(0xFFFFF5CC);
  MakeName(0xFFFFF5CC, "reg_TIER11");

  MakeWord(0xFFFFF600);
  MakeName(0xFFFFF600, "reg_TCNT2A");

  MakeWord(0xFFFFF602);
  MakeName(0xFFFFF602, "reg_TCNT2B");

  MakeWord(0xFFFFF604);
  MakeName(0xFFFFF604, "reg_GR2A");

  MakeWord(0xFFFFF606);
  MakeName(0xFFFFF606, "reg_GR2B");

  MakeWord(0xFFFFF608);
  MakeName(0xFFFFF608, "reg_GR2C");

  MakeWord(0xFFFFF60A);
  MakeName(0xFFFFF60A, "reg_GR2D");

  MakeWord(0xFFFFF60C);
  MakeName(0xFFFFF60C, "reg_GR2E");

  MakeWord(0xFFFFF60E);
  MakeName(0xFFFFF60E, "reg_GR2F");

  MakeWord(0xFFFFF610);
  MakeName(0xFFFFF610, "reg_GR2G");

  MakeWord(0xFFFFF612);
  MakeName(0xFFFFF612, "reg_GR2H");

  MakeWord(0xFFFFF614);
  MakeName(0xFFFFF614, "reg_OCR2A");

  MakeWord(0xFFFFF616);
  MakeName(0xFFFFF616, "reg_OCR2B");

  MakeWord(0xFFFFF618);
  MakeName(0xFFFFF618, "reg_OCR2C");

  MakeWord(0xFFFFF61A);
  MakeName(0xFFFFF61A, "reg_OCR2D");

  MakeWord(0xFFFFF61C);
  MakeName(0xFFFFF61C, "reg_OCR2E");

  MakeWord(0xFFFFF61E);
  MakeName(0xFFFFF61E, "reg_OCR2F");

  MakeWord(0xFFFFF620);
  MakeName(0xFFFFF620, "reg_OCR2G");

  MakeWord(0xFFFFF622);
  MakeName(0xFFFFF622, "reg_OCR2H");

  MakeWord(0xFFFFF624);
  MakeName(0xFFFFF624, "reg_OSBR2");

  MakeByte(0xFFFFF626);
  MakeName(0xFFFFF626, "reg_TIOR2B");

  MakeByte(0xFFFFF627);
  MakeName(0xFFFFF627, "reg_TIOR2A");

  MakeByte(0xFFFFF628);
  MakeName(0xFFFFF628, "reg_TIOR2D");

  MakeByte(0xFFFFF629);
  MakeName(0xFFFFF629, "reg_TIOR2C");

  MakeByte(0xFFFFF62A);
  MakeName(0xFFFFF62A, "reg_TCR2B");

  MakeByte(0xFFFFF62B);
  MakeName(0xFFFFF62B, "reg_TCR2A");

  MakeWord(0xFFFFF62C);
  MakeName(0xFFFFF62C, "reg_TSR2A");

  MakeWord(0xFFFFF62E);
  MakeName(0xFFFFF62E, "reg_TSR2B");

  MakeWord(0xFFFFF630);
  MakeName(0xFFFFF630, "reg_TIER2A");

  MakeWord(0xFFFFF632);
  MakeName(0xFFFFF632, "reg_TIER2B");

  MakeWord(0xFFFFF640);
  MakeName(0xFFFFF640, "reg_DCNT8A");

  MakeWord(0xFFFFF642);
  MakeName(0xFFFFF642, "reg_DNCT8B");

  MakeWord(0xFFFFF644);
  MakeName(0xFFFFF644, "reg_DNCT8C");

  MakeWord(0xFFFFF646);
  MakeName(0xFFFFF646, "reg_DCNT8D");

  MakeWord(0xFFFFF648);
  MakeName(0xFFFFF648, "reg_DCNT8E");

  MakeWord(0xFFFFF64A);
  MakeName(0xFFFFF64A, "reg_DCNT8F");

  MakeWord(0xFFFFF64C);
  MakeName(0xFFFFF64C, "reg_DCNT8G");

  MakeWord(0xFFFFF64E);
  MakeName(0xFFFFF64E, "reg_DCNT8H");

  MakeWord(0xFFFFF650);
  MakeName(0xFFFFF650, "reg_DCNT8I");

  MakeWord(0xFFFFF652);
  MakeName(0xFFFFF652, "reg_DCNT8J");

  MakeWord(0xFFFFF654);
  MakeName(0xFFFFF654, "reg_DCNT8K");

  MakeWord(0xFFFFF656);
  MakeName(0xFFFFF656, "reg_DCNT8L");

  MakeWord(0xFFFFF658);
  MakeName(0xFFFFF658, "reg_DCNT8M");

  MakeWord(0xFFFFF65A);
  MakeName(0xFFFFF65A, "reg_DCNT8N");

  MakeWord(0xFFFFF65C);
  MakeName(0xFFFFF65C, "reg_DCNT8O");

  MakeWord(0xFFFFF65E);
  MakeName(0xFFFFF65E, "reg_DCNT8P");

  MakeWord(0xFFFFF660);
  MakeName(0xFFFFF660, "reg_RLDR8");

  MakeWord(0xFFFFF662);
  MakeName(0xFFFFF662, "reg_TCNR");

  MakeWord(0xFFFFF664);
  MakeName(0xFFFFF664, "reg_OTR");

  MakeWord(0xFFFFF666);
  MakeName(0xFFFFF666, "reg_DSTR");

  MakeByte(0xFFFFF668);
  MakeName(0xFFFFF668, "reg_TCR8");

  MakeWord(0xFFFFF66A);
  MakeName(0xFFFFF66A, "reg_TSR8");

  MakeWord(0xFFFFF66C);
  MakeName(0xFFFFF66C, "reg_TIER8");

  MakeByte(0xFFFFF66E);
  MakeName(0xFFFFF66E, "reg_RLDENR");

  MakeByte(0xFFFFF680);
  MakeName(0xFFFFF680, "reg_ECNT9A");

  MakeByte(0xFFFFF682);
  MakeName(0xFFFFF682, "reg_ECNT9B");

  MakeByte(0xFFFFF684);
  MakeName(0xFFFFF684, "reg_ECNT9C");

  MakeByte(0xFFFFF686);
  MakeName(0xFFFFF686, "reg_ECNT9D");

  MakeByte(0xFFFFF688);
  MakeName(0xFFFFF688, "reg_ECNT9E");

  MakeByte(0xFFFFF68A);
  MakeName(0xFFFFF68A, "reg_ECNT9F");

  MakeByte(0xFFFFF68C);
  MakeName(0xFFFFF68C, "reg_GR9A");

  MakeByte(0xFFFFF68E);
  MakeName(0xFFFFF68E, "reg_GR9B");

  MakeByte(0xFFFFF690);
  MakeName(0xFFFFF690, "reg_GR9C");

  MakeByte(0xFFFFF692);
  MakeName(0xFFFFF692, "reg_GR9D");

  MakeByte(0xFFFFF694);
  MakeName(0xFFFFF694, "reg_GR9E");

  MakeByte(0xFFFFF696);
  MakeName(0xFFFFF696, "reg_GR9F");

  MakeByte(0xFFFFF698);
  MakeName(0xFFFFF698, "reg_TCR9A");

  MakeByte(0xFFFFF69A);
  MakeName(0xFFFFF69A, "reg_TCR9B");

  MakeByte(0xFFFFF69C);
  MakeName(0xFFFFF69C, "reg_TCR9C");

  MakeWord(0xFFFFF69E);
  MakeName(0xFFFFF69E, "reg_TSR9");

  MakeWord(0xFFFFF6A0);
  MakeName(0xFFFFF6A0, "reg_TIER9");

  MakeWord(0xFFFFF6C0);
  MakeName(0xFFFFF6C0, "reg_TCNT10AH");

  MakeWord(0xFFFFF6C2);
  MakeName(0xFFFFF6C2, "reg_TCNT10AL");

  MakeByte(0xFFFFF6C4);
  MakeName(0xFFFFF6C4, "reg_TCNT10B");

  MakeWord(0xFFFFF6C6);
  MakeName(0xFFFFF6C6, "reg_TCNT10C");

  MakeByte(0xFFFFF6C8);
  MakeName(0xFFFFF6C8, "reg_TCNT10D");

  MakeWord(0xFFFFF6CA);
  MakeName(0xFFFFF6CA, "reg_TCNT10E");

  MakeWord(0xFFFFF6CC);
  MakeName(0xFFFFF6CC, "reg_TCNT10F");

  MakeWord(0xFFFFF6CE);
  MakeName(0xFFFFF6CE, "reg_TCNT10G");

  MakeWord(0xFFFFF6D0);
  MakeName(0xFFFFF6D0, "reg_ICR10AH");

  MakeWord(0xFFFFF6D2);
  MakeName(0xFFFFF6D2, "reg_ICR10AL");

  MakeWord(0xFFFFF6D4);
  MakeName(0xFFFFF6D4, "reg_OCR10AH");

  MakeWord(0xFFFFF6D6);
  MakeName(0xFFFFF6D6, "reg_OCR10AL");

  MakeByte(0xFFFFF6D8);
  MakeName(0xFFFFF6D8, "reg_OCR10B");

  MakeWord(0xFFFFF6DA);
  MakeName(0xFFFFF6DA, "reg_RLD10C");

  MakeWord(0xFFFFF6DC);
  MakeName(0xFFFFF6DC, "reg_GR10G");

  MakeByte(0xFFFFF6DE);
  MakeName(0xFFFFF6DE, "reg_TCNT10H");

  MakeByte(0xFFFFF6E0);
  MakeName(0xFFFFF6E0, "reg_NCR10");

  MakeByte(0xFFFFF6E2);
  MakeName(0xFFFFF6E2, "reg_TIOR10");

  MakeByte(0xFFFFF6E4);
  MakeName(0xFFFFF6E4, "reg_TCR10");

  MakeWord(0xFFFFF6E6);
  MakeName(0xFFFFF6E6, "reg_TCCLR10");

  MakeWord(0xFFFFF6E8);
  MakeName(0xFFFFF6E8, "reg_TSR10");

  MakeWord(0xFFFFF6EA);
  MakeName(0xFFFFF6EA, "reg_TIER10");

  MakeWord(0xFFFFF700);
  MakeName(0xFFFFF700, "reg_POPCR");

  MakeByte(0xFFFFF708);
  MakeName(0xFFFFF708, "reg_SYSCR");

  MakeByte(0xFFFFF70A);
  MakeName(0xFFFFF70A, "reg_MSTCR_wr");

  MakeByte(0xFFFFF70B);
  MakeName(0xFFFFF70B, "reg_MSTCR_rd");

  MakeWord(0xFFFFF710);
  MakeName(0xFFFFF710, "reg_CMSTR");

  MakeWord(0xFFFFF712);
  MakeName(0xFFFFF712, "reg_CMCSR0");

  MakeWord(0xFFFFF714);
  MakeName(0xFFFFF714, "reg_CMCNT0");

  MakeWord(0xFFFFF716);
  MakeName(0xFFFFF716, "reg_CMCOR0");

  MakeWord(0xFFFFF718);
  MakeName(0xFFFFF718, "reg_CMCSR1");

  MakeWord(0xFFFFF71A);
  MakeName(0xFFFFF71A, "reg_CMCNT1");

  MakeWord(0xFFFFF71C);
  MakeName(0xFFFFF71C, "reg_CMCOR1");

  MakeWord(0xFFFFF720);
  MakeName(0xFFFFF720, "reg_PAIOR");

  MakeWord(0xFFFFF722);
  MakeName(0xFFFFF722, "reg_PACRH");

  MakeWord(0xFFFFF724);
  MakeName(0xFFFFF724, "reg_PACRL");

  MakeWord(0xFFFFF726);
  MakeName(0xFFFFF726, "reg_PADR");

  MakeWord(0xFFFFF728);
  MakeName(0xFFFFF728, "reg_PHIOR");

  MakeWord(0xFFFFF72A);
  MakeName(0xFFFFF72A, "reg_PHCR");

  MakeWord(0xFFFFF72C);
  MakeName(0xFFFFF72C, "reg_PHDR");

  MakeByte(0xFFFFF72E);
  MakeName(0xFFFFF72E, "reg_ADTRGR1");

  MakeWord(0xFFFFF730);
  MakeName(0xFFFFF730, "reg_PBIOR");

  MakeWord(0xFFFFF732);
  MakeName(0xFFFFF732, "reg_PBCRH");

  MakeWord(0xFFFFF734);
  MakeName(0xFFFFF734, "reg_PBCRL");

  MakeWord(0xFFFFF736);
  MakeName(0xFFFFF736, "reg_PBIR");

  MakeWord(0xFFFFF738);
  MakeName(0xFFFFF738, "reg_PBDR");

  MakeWord(0xFFFFF73A);
  MakeName(0xFFFFF73A, "reg_PCIOR");

  MakeWord(0xFFFFF73C);
  MakeName(0xFFFFF73C, "reg_PCCR");

  MakeWord(0xFFFFF73E);
  MakeName(0xFFFFF73E, "reg_PCDR");

  MakeWord(0xFFFFF740);
  MakeName(0xFFFFF740, "reg_PDIOR");

  MakeWord(0xFFFFF742);
  MakeName(0xFFFFF742, "reg_PDCRH");

  MakeWord(0xFFFFF744);
  MakeName(0xFFFFF744, "reg_PDCRL");

  MakeWord(0xFFFFF746);
  MakeName(0xFFFFF746, "reg_PDDR");

  MakeWord(0xFFFFF748);
  MakeName(0xFFFFF748, "reg_PFIOR");

  MakeWord(0xFFFFF74A);
  MakeName(0xFFFFF74A, "reg_PFCRH");

  MakeWord(0xFFFFF74C);
  MakeName(0xFFFFF74C, "reg_PFCRL");

  MakeWord(0xFFFFF74E);
  MakeName(0xFFFFF74E, "reg_PFDR");

  MakeWord(0xFFFFF750);
  MakeName(0xFFFFF750, "reg_PEIOR");

  MakeWord(0xFFFFF752);
  MakeName(0xFFFFF752, "reg_PECR");

  MakeByte(0xFFFFF754);
  MakeName(0xFFFFF754, "reg_PEDR");

  MakeByte(0xFFFFF755);
  MakeName(0xFFFFF755, "reg_PE7DR");

  MakeWord(0xFFFFF760);
  MakeName(0xFFFFF760, "reg_PGIOR");

  MakeWord(0xFFFFF762);
  MakeName(0xFFFFF762, "reg_PGCR");

  MakeWord(0xFFFFF764);
  MakeName(0xFFFFF764, "reg_PGDR");

  MakeWord(0xFFFFF766);
  MakeName(0xFFFFF766, "reg_PJIOR");

  MakeWord(0xFFFFF768);
  MakeName(0xFFFFF768, "reg_PJCRH");

  MakeWord(0xFFFFF76A);
  MakeName(0xFFFFF76A, "reg_PJCRL");

  MakeWord(0xFFFFF76C);
  MakeName(0xFFFFF76C, "reg_PJDR");

  MakeByte(0xFFFFF76E);
  MakeName(0xFFFFF76E, "reg_ADTRGR0");

  MakeWord(0xFFFFF770);
  MakeName(0xFFFFF770, "reg_PKIOR");

  MakeWord(0xFFFFF772);
  MakeName(0xFFFFF772, "reg_PKCRH");

  MakeWord(0xFFFFF774);
  MakeName(0xFFFFF774, "reg_PKCRL");

  MakeWord(0xFFFFF776);
  MakeName(0xFFFFF776, "reg_PKIR");

  MakeWord(0xFFFFF778);
  MakeName(0xFFFFF778, "reg_PKDR");

  MakeByte(0xFFFFF77A);
  MakeName(0xFFFFF77A, "reg_to");

  MakeByte(0xFFFFF800);
  MakeName(0xFFFFF800, "reg_ADDR0H");

  MakeByte(0xFFFFF801);
  MakeName(0xFFFFF801, "reg_ADDR0L");

  MakeByte(0xFFFFF802);
  MakeName(0xFFFFF802, "reg_ADDR1H");

  MakeByte(0xFFFFF803);
  MakeName(0xFFFFF803, "reg_ADDR1L");

  MakeByte(0xFFFFF804);
  MakeName(0xFFFFF804, "reg_ADDR2H");

  MakeByte(0xFFFFF805);
  MakeName(0xFFFFF805, "reg_ADDR2L");

  MakeByte(0xFFFFF806);
  MakeName(0xFFFFF806, "reg_ADDR3H");

  MakeByte(0xFFFFF807);
  MakeName(0xFFFFF807, "reg_ADDR3L");

  MakeByte(0xFFFFF808);
  MakeName(0xFFFFF808, "reg_ADDR4H");

  MakeByte(0xFFFFF809);
  MakeName(0xFFFFF809, "reg_ADDR4L");

  MakeByte(0xFFFFF80A);
  MakeName(0xFFFFF80A, "reg_ADDR5H");

  MakeByte(0xFFFFF80B);
  MakeName(0xFFFFF80B, "reg_ADDR5L");

  MakeByte(0xFFFFF80C);
  MakeName(0xFFFFF80C, "reg_ADDR6H");

  MakeByte(0xFFFFF80D);
  MakeName(0xFFFFF80D, "reg_ADDR6L");

  MakeByte(0xFFFFF80E);
  MakeName(0xFFFFF80E, "reg_ADDR7H");

  MakeByte(0xFFFFF80F);
  MakeName(0xFFFFF80F, "reg_ADDR7L");

  MakeByte(0xFFFFF810);
  MakeName(0xFFFFF810, "reg_ADDR8H");

  MakeByte(0xFFFFF811);
  MakeName(0xFFFFF811, "reg_ADDR8L");

  MakeByte(0xFFFFF812);
  MakeName(0xFFFFF812, "reg_ADDR9H");

  MakeByte(0xFFFFF813);
  MakeName(0xFFFFF813, "reg_ADDR9L");

  MakeByte(0xFFFFF814);
  MakeName(0xFFFFF814, "reg_ADDR10H");

  MakeByte(0xFFFFF815);
  MakeName(0xFFFFF815, "reg_ADDR10L");

  MakeByte(0xFFFFF816);
  MakeName(0xFFFFF816, "reg_ADDR11H");

  MakeByte(0xFFFFF817);
  MakeName(0xFFFFF817, "reg_ADDR11L");

  MakeByte(0xFFFFF818);
  MakeName(0xFFFFF818, "reg_ADCSR0");

  MakeByte(0xFFFFF819);
  MakeName(0xFFFFF819, "reg_ADCR0");

  MakeByte(0xFFFFF820);
  MakeName(0xFFFFF820, "reg_ADDR12H");

  MakeByte(0xFFFFF821);
  MakeName(0xFFFFF821, "reg_ADDR12L");

  MakeByte(0xFFFFF822);
  MakeName(0xFFFFF822, "reg_ADDR13H");

  MakeByte(0xFFFFF823);
  MakeName(0xFFFFF823, "reg_ADDR13L");

  MakeByte(0xFFFFF824);
  MakeName(0xFFFFF824, "reg_ADDR14H");

  MakeByte(0xFFFFF825);
  MakeName(0xFFFFF825, "reg_ADDR14L");

  MakeByte(0xFFFFF826);
  MakeName(0xFFFFF826, "reg_ADDR15H");

  MakeByte(0xFFFFF827);
  MakeName(0xFFFFF827, "reg_ADDR15L");

  MakeByte(0xFFFFF838);
  MakeName(0xFFFFF838, "reg_ADCSR1");

  MakeByte(0xFFFFF839);
  MakeName(0xFFFFF839, "reg_ADCR1");

  Message("done.\n");
}
