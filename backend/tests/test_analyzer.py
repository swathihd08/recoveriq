import io

from PIL import Image
from pypdf import PdfWriter

from backend.analyzer import analyze_bytes, repair_image_payload, verify_payload


def test_detects_pdf_signature_and_end_marker():
    pdf_buffer = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.write(pdf_buffer)
    results = analyze_bytes("sample.img", b"\x00\x01" + pdf_buffer.getvalue())
    pdf = next(item for item in results if item.file_type == "PDF")
    assert pdf.offset == 2
    assert pdf.sha256
    assert pdf.offset == 2
    assert pdf.status == "Recovered"


def test_detects_jpeg_at_nonzero_offset():
    results = analyze_bytes("sample.img", b"padding\xff\xd8\xff\xe0JFIF\xff\xd9tail")
    jpeg = next(item for item in results if item.file_type == "JPEG")
    assert jpeg.offset == 7
    assert jpeg.payload.endswith(b"\xff\xd9")


def test_does_not_duplicate_text_inside_carved_jpeg():
    payload = b"\xff\xd8\xff" + (b"camera evidence pixel data " * 4) + b"\xff\xd9"
    results = analyze_bytes("sample.img", payload)
    assert [item.file_type for item in results] == ["JPEG"]


def test_extracts_long_readable_text_runs():
    content = b"From: analyst@example.test\nSubject: recovered record\n" + b"Evidence fragment with repeated context and details. " * 3
    results = analyze_bytes("dump.bin", content)
    assert any(item.file_type == "TEXT" for item in results)


def test_marker_only_image_is_not_structurally_verified():
    result = verify_payload("JPEG", b"\xff\xd8\xfffake image data\xff\xd9")
    assert result["signature_valid"]
    assert result["ending_valid"]
    assert not result["container_valid"]
    assert not result["verified"]


def test_valid_jpeg_and_png_pass_container_verification():
    for format_name, file_type in (("JPEG", "JPEG"), ("PNG", "PNG")):
        buffer = io.BytesIO()
        Image.new("RGB", (12, 8), "#287653").save(buffer, format=format_name)
        result = verify_payload(file_type, buffer.getvalue())
        assert result["signature_valid"]
        assert result["ending_valid"]
        assert result["container_valid"]
        assert result["verified"]


def test_repair_salvages_truncated_jpeg_and_png_as_verified_copies():
    for format_name, file_type, removed_bytes in (("JPEG", "JPEG", 2), ("PNG", "PNG", 12)):
        buffer = io.BytesIO()
        Image.new("RGB", (12, 8), "#287653").save(buffer, format=format_name)
        damaged = buffer.getvalue()[:-removed_bytes]

        repaired = repair_image_payload(file_type, damaged)

        assert repaired != damaged
        assert verify_payload(file_type, repaired)["verified"]
