/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates memory maps and disassembles entry points.
 */
public class CasioLoopyLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Casio Loopy Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Too small for game carts
		if (provider.length() < 0x100000) {
			return loadSpecs;
		}

		// FIXME: Support word-swapped ROMs
		BinaryReader reader = new BinaryReader(provider, false);

		// Heuristic 1: Start of ROM header
		byte[] bytes = reader.readByteArray(0, 6);
		Pattern magic = Pattern.compile("\\x0e\\x00\\x00\\x80\\x0e[\\x1f\\x2f]");
		Matcher matcher = magic.matcher(new ByteCharSequence(bytes));
		boolean isLoopyCart = matcher.find();

		// Heuristic 2: Entry point signature for "Video Seal Wordprocessor / Magical Shop"
		if (!isLoopyCart) {
			bytes = reader.readByteArray(0x480, 0x10);
			magic = Pattern.compile("\\xdf\\x05\\xd0\\x06\\x40\\x2b\\x00\\x09\\xdf\\x03\\xd0\\x05\\x40\\x2b\\x00\\x09");
			matcher = magic.matcher(new ByteCharSequence(bytes));
			isLoopyCart = matcher.find();
		}

		if (isLoopyCart) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH:BE:32:SH-1", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider,
			LoadSpec loadSpec,
			List<Option> options,
			Program program,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		InputStream romStream = provider.getInputStream(0);

		InputStream biosStream = null;
		File biosFile = new File("/tmp/hd6437021.lsi302");
		if (biosFile.isFile()) {
			biosStream = new FileInputStream(biosFile);
			monitor.setMessage(String.format("Loading BIOS @ %s", biosFile));
		} else {
			int choice = OptionDialog.showOptionNoCancelDialog(
				null,
				"BIOS mapping",
				"Load BIOS file?",
				"Yes",
				"No (Just create empty mapping)",
				OptionDialog.QUESTION_MESSAGE
			);
			if (choice == OptionDialog.OPTION_ONE) {
				GhidraFileChooser chooser = new GhidraFileChooser(null);
				chooser.setTitle("Open BIOS file");
				File file = chooser.getSelectedFile(true);
				if (file != null) {
					biosStream = new FileInputStream(file);
				}
			}
		}

		final long biosSize = Math.min(biosStream.available(), 0x8000L);
		final long cartSize = Math.min(romStream.available(), 0x400000L);
		createSegment(fpa, biosStream, "BIOS_ROM",  0x00000000L, biosSize, true, false, true, false, log);
		createSegment(fpa, null,       "WORK_DRAM", 0x01000000L, 0x80000L, true, true, false, true, log);
		createSegment(fpa, null,       "CART_SRAM", 0x02000000L, 0x400000L, true, true, false, true, log);
		createSegment(fpa, null,       "IO",        0x04000000L, 0x100000L, true, true, false, true, log);
		createSegment(fpa, romStream,  "CART_ROM",  0x06000000L, cartSize, true, false, true, false, log);

		for (int i = 0; i < 32; i++) {
			createMirrorSegment(program.getMemory(), fpa, "WORK_DRAM_" + String.format("%02d", i), 0x01000000L, 0x09000000L + (i * 0x80000L), 0x80000L, log);
		}
		createMirrorSegment(program.getMemory(), fpa, "IO_",         0x04000000L, 0x0c000000L, 0x100000L, log);
		createMirrorSegment(program.getMemory(), fpa, "CART_ROM_",   0x06000000L, 0x0e000000L, cartSize, log);

		createNames(fpa, program, 0x04000000L, log);
		createNames(fpa, program, 0x0c000000L, log);

		// BIOS ROM entry point
		Address biosEntry = fpa.toAddr(0x00000400L);
		try {
			DisassembleCommand cmd = new DisassembleCommand(biosEntry, null, true);
			cmd.applyTo(program, TaskMonitor.DUMMY);
			fpa.createFunction(biosEntry, "bios_reset");
			fpa.addEntryPoint(biosEntry);
		} catch (Exception e) {
			log.appendException(e);
		}

		// Game ROM entry point
		Address entry = fpa.toAddr(0x06000480L);
		try {
			DisassembleCommand cmd = new DisassembleCommand(entry, null, true);
			cmd.applyTo(program, TaskMonitor.DUMMY);
			fpa.createFunction(entry, "reset");
			fpa.addEntryPoint(entry);
		} catch (Exception e) {
			log.appendException(e);
		}

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createNames(FlatProgramAPI fpa, Program program, long base, MessageLog log) {
		createNamedArray(fpa, program, base + 0x00000000L, "BITMAP", 0x20000, ByteDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x00020000L, "BITMAP_", 0x20000, ByteDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x00040000L, "VRAM", 0x10000, ByteDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x00050000L, "SPRITE_RAM", 0x200, ByteDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x00051000L, "PALETTE", 0x200, ByteDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x00052000L, "READBACK", 0x200, ByteDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00058000L, "SYSTEM_CONTROL", ByteDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00058002L, "HPOS", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00058004L, "VPOS", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00058006L, "REG_58006", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00058008L, "REG_58008", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059000L, "BMP_VRAM_X", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059008L, "BMP_VRAM_Y", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059010L, "BMP_SCREEN_X", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059018L, "BMP_SCREEN_Y", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059020L, "BMP_SIZE_X", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059028L, "BMP_SIZE_Y", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059030L, "BMP_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059040L, "BMP_COLOR", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00059050L, "BMP_SPAN", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a000L, "TILEMAP_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a002L, "TILEMAP_SCROLL_X", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a004L, "TILEMAP_SCROLL_Y", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a006L, "TILEMAP_SCROLL_X", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a008L, "TILEMAP_SCROLL_Y", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a00aL, "TILEMAP_COLOR", DWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a010L, "SPRITE_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a012L, "SPRITE_COLOR", DWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005a020L, "TILEMAP_PAGE", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005b000L, "LAYER_CONTROL_0", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005b002L, "LAYER_ENABLE", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005b004L, "LAYER_CONTROL_2", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005b006L, "COLOR", DWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005b00aL, "READBACK_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005c000L, "INT_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005c002L, "SCREEN_WIDTH", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005c004L, "SCREEN_HEIGHT", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d000L, "REG_5D000", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d010L, "CONTROLLER_0", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d012L, "CONTROLLER_1", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d014L, "CONTROLLER_2", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d020L, "REG_5D020", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d030L, "REG_5D030", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d040L, "REG_5D040", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d042L, "REG_5D042", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d044L, "REG_5D044", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d050L, "MOUSE1", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d052L, "MOUSE2", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005d054L, "REG_5D054", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005e000L, "REG_5E000", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005e002L, "CLEAR_MASK", QWordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x0005e004L, "CLEAR_COLOR", QWordDataType.dataType, log);
		createNamedArray(fpa, program, base + 0x0005f000L, "FAST_CLEAR", 0x400, ByteDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00060000L, "REG_60000", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x00080000L, "SOUND_CONTROL", WordDataType.dataType, log);
		createNamedData(fpa, program, base + 0x000a0000L, "REG_A0000", WordDataType.dataType, log);
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			long address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			int numElements,
			DataType type,
			MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	public class ByteCharSequence implements CharSequence {

		private final byte[] data;
		private final int length;
		private final int offset;

		public ByteCharSequence(byte[] data) {
			this(data, 0, data.length);
		}

		public ByteCharSequence(byte[] data, int offset, int length) {
			this.data = data;
			this.offset = offset;
			this.length = length;
		}

		@Override
		public int length() {
			return this.length;
		}

		@Override
		public char charAt(int index) {
			return (char) (data[offset + index] & 0xff);
		}

		@Override
		public CharSequence subSequence(int start, int end) {
			return new ByteCharSequence(data, offset + start, end - start);
		}
	}
}
