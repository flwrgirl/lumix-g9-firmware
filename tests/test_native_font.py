# SPDX-License-Identifier: MIT
"""Firmware-free controls for pixel export, input bounds and CPU transport."""
import struct
import unittest
import zlib
from unittest import mock
from tools import font_runtime as font
from tools import qemu_display as display
from tools import qemu_g9_probe as qemu
from tools.render_g9_font import png_grayscale


class NativePixelControls(unittest.TestCase):
    def test_png_preserves_every_native_gray_level_and_has_valid_crcs(self):
        raw=bytes(range(16))*16
        encoded=png_grayscale(raw,16,16)
        self.assertEqual(encoded[:8],b'\x89PNG\r\n\x1a\n')
        offset=8;compressed=bytearray();dimensions=None
        while offset<len(encoded):
            length=struct.unpack_from('>I',encoded,offset)[0]
            kind=encoded[offset+4:offset+8];payload=encoded[offset+8:offset+8+length]
            checksum=struct.unpack_from('>I',encoded,offset+8+length)[0]
            self.assertEqual(checksum,zlib.crc32(kind+payload)&0xffffffff)
            if kind==b'IHDR':dimensions=struct.unpack('>IIBBBBB',payload)
            if kind==b'IDAT':compressed.extend(payload)
            offset+=length+12
        self.assertEqual(dimensions,(16,16,8,0,0,0,0))
        scanlines=zlib.decompress(compressed)
        self.assertEqual(scanlines,b''.join(b'\0'+bytes(v*17 for v in raw[row*16:row*16+16]) for row in range(16)))

    def test_incomplete_or_out_of_range_bitmaps_are_rejected(self):
        for raw,width,height in ((b'\0',16,16),(bytes([16])*256,16,16),(b'',0,0)):
            with self.subTest(width=width,height=height),self.assertRaises(ValueError):
                png_grayscale(raw,width,height)

    def test_display_adapter_writes_only_its_framebuffer_and_controller(self):
        pipe=mock.Mock();pipe.command.return_value=b'OK'
        display.present(pipe,bytes(range(16))*16,16,16)
        requests=[call.args[0] for call in pipe.command.call_args_list]
        addresses=[int(request[1:request.index(',')],16) for request in requests]
        self.assertEqual(addresses,[display.FRAMEBUFFER,display.PL110,display.PL110+4,
                                    display.PL110+0x10,display.PL110+0x14,display.PL110+0x18])
        payload=bytes.fromhex(requests[0].split(':')[1])
        self.assertEqual(payload[:12],bytes((0,0,0,0,17,17,17,0,34,34,34,0)))
        pipe.reset_mock()
        with self.assertRaises(ValueError):display.present(pipe,bytes(17*16),17,16)
        pipe.command.assert_not_called()

    def test_text_limit_counts_utf16_units_and_excludes_nul(self):
        self.assertEqual(font.text_arguments('DC-G9',512,80),'DC-G9\0'.encode('utf-16-le'))
        font.text_arguments('\U0001f4f7'*25,512,80)
        for text in ('','a\0b','\U0001f4f7'*26):
            with self.subTest(text=text),self.assertRaises(ValueError):font.text_arguments(text,512,80)
        for dimensions in ((15,80),(721,80),(512,481)):
            with self.assertRaises(ValueError):font.text_arguments('x',*dimensions)


class CpuSelectionControls(unittest.TestCase):
    def test_stopped_cpu_is_selected_before_reading_its_registers(self):
        pipe=qemu.GdbPipe.__new__(qemu.GdbPipe);pipe.command=mock.Mock(return_value=b'OK')
        pipe.current_thread='p01.01'
        pipe.select_stop_thread(b'T05thread:p01.03;')
        self.assertEqual(pipe.current_thread,'p01.03')
        pipe.command.assert_called_once_with('Hgp01.03')
        with self.assertRaises(ValueError):pipe.select_stop_thread(b'T05thread:invalid;')

    def test_repeated_native_calls_do_not_duplicate_exception_breakpoints(self):
        pipe=qemu.GdbPipe.__new__(qemu.GdbPipe)
        pipe.current_thread='p01.01';pipe.set_register=mock.Mock()
        def reply(request,**kwargs):
            return b'T05thread:p01.01;' if request.startswith('vCont;c:') else b'OK'
        pipe.command=mock.Mock(side_effect=reply)
        def register(index):
            if index==15:return 0x010ff000
            if index==13:return 0x010f0000
            if 4<=index<12:return 0x55aa0000+index
            return 0
        pipe.register=mock.Mock(side_effect=register)
        pipe.call(0x01000000);pipe.call(0x01000000)
        breakpoints=[call.args[0] for call in pipe.command.call_args_list if call.args[0].startswith('Z0,')]
        self.assertEqual(len(breakpoints),7)
        self.assertEqual(len(set(breakpoints)),7)


if __name__=='__main__':unittest.main()
