"""LSB Image Steganographer: hide and reveal secret text inside images.

A Drafter website where the user uploads an image, hides a text message in the
least significant bit (LSB) of one color channel (Red, Green, or Blue), and
downloads the new image. The same site can read a hidden message back out.

Nothing is read from or written to the computer's folders. Uploaded images are
processed in memory, so the site also works when deployed to GitHub Pages.

ADVANCED TECHNIQUES USED (not covered in class), documented here and where used:
  * try/except: Used in `open_image_bytes` so a bad upload gives a friendly error
    message instead of crashing the site.
  * bytes / bytearray: An image is just a long run of numbers (R, G, B, R, G, B...).
    `Image.tobytes()` gives us those numbers and a `bytearray` lets us change them.
  * Extended slices like `raw[2::3]`: Means "start at index 2, then take every 3rd
    item", which picks out one color channel (Blue here) from the R,G,B run.
  * Bitwise operators: `value & 1` reads the last bit of a number, and
    `(value & 0xFE) | bit` replaces the last bit of a number with `bit`.
  * int.to_bytes / int.from_bytes: Turn a number into raw bytes and back (the
    message length is stored inside the image so we know where the message ends).
  * io.BytesIO and base64: BytesIO acts like a file that lives in memory, and base64
    turns image bytes into plain text so the image can sit in the State and be shown
    or downloaded by the browser as a "data URL".
  * html.escape: Stops a user's message from being treated as HTML code on the page.
  * Raw HTML in page content: Drafter allows HTML inside strings, used for styling.
  * Union type hints like `str | None`: A function that returns text OR nothing.
"""

import base64
import html
import io
from dataclasses import dataclass

from bakery import assert_equal
from PIL import Image as PILImage
from drafter import (
    Page,
    Button,
    TextArea,
    SelectBox,
    FileUpload,
    Download,
    RawHTML,
    Table,
    NumberedList,
    Header,
    HorizontalRule,
    LineBreak,
    set_site_information,
    hide_debug_information,
    set_website_title,
    set_website_framed,
    start_server,
    route,
)


# ---------------------------------------------------------------------------
# Constants (global constants are allowed; nothing here is ever modified)
# ---------------------------------------------------------------------------
CHANNELS = ("Red", "Green", "Blue")
MAGIC = b"STEG"           # Marker stored first inside the image: "a message follows"
HEADER_BYTES = 8          # 4 bytes of MAGIC + 4 bytes holding the message length
PREVIEW_SIZE = 360        # Longest side, in pixels, of the previews shown on pages
MAX_PIXELS = 2_000_000    # Largest image accepted (about 1400 x 1400)
DATA_URL_START = "data:image/png;base64,"

# Site information required by the course (see the deployment instructions).

set_site_information(
    author="Jayden Glatt (jayglatt@udel.edu)",
    description="""Hide secret text messages inside images using LSB steganography.
    Upload an image, choose a color channel, and download the modified image.""",
    sources=["Official Drafter documentation",
             "Conversations with Gemini and Claude (uploaded to this repository)"],
    planning=["your_planning_document.pdf"],
    links=["https://github.com/jayden-glatt/steganography-project"],
)
hide_debug_information()  # Comment this line out while debugging
set_website_title("LSB Image Steganographer")
set_website_framed(False)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class StegoRecord:
    """One entry in the activity history."""
    image_size: str        # For example "600x400 pixels"
    action: str            # "Encoded" or "Decoded"
    message_length: int    # Number of characters in the message
    channel_used: str      # "Red", "Green", or "Blue"


@dataclass
class State:
    """Everything the website remembers between pages."""
    history: list[StegoRecord]
    source_preview: str      # Small preview (a data URL) of the image just used
    encoded_preview: str     # Small preview (a data URL) of the newest encoded image
    encoded_data: str        # Full newest encoded PNG as base64 text ("" if none yet)
    extracted_message: str   # Text found by the most recent decode
    error_alert: str         # Error shown on a form page ("" means no error)
    last_action: str         # "Encoded", "Decoded", or "" if nothing done yet
    last_channel: str        # Channel used most recently, reused as the form default
    draft_message: str       # Message typed in the encode form, kept after an error


def new_state() -> State:
    """Returns a brand new State for a first-time visitor."""
    return State([], "", "", "", "", "", "", "Blue", "")


# ---------------------------------------------------------------------------
# Steganography engine (works on in-memory images so it can be unit tested)
# ---------------------------------------------------------------------------
def channel_offset(channel: str) -> int:
    """Returns where a color channel sits inside each R,G,B pixel (0, 1, or 2)."""
    if channel == "Red":
        return 0
    elif channel == "Green":
        return 1
    return 2


def bytes_to_bits(data: bytes) -> list[int]:
    """Converts bytes into a list of bits (0 or 1), most significant bit first."""
    bits = []
    for byte in data:
        for position in range(7, -1, -1):
            bits.append((byte >> position) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """Converts a list of bits back into bytes, ignoring any leftover bits."""
    result = bytearray()
    for start in range(0, len(bits) - len(bits) % 8, 8):
        value = 0
        for bit in bits[start:start + 8]:
            value = value * 2 + bit
        result.append(value)
    return bytes(result)


def max_message_bytes(width: int, height: int) -> int:
    """Returns how many message bytes fit in an image (1 bit per pixel, minus the header)."""
    return max(0, (width * height) // 8 - HEADER_BYTES)


def embed_message(img: PILImage.Image, message: str, channel: str) -> PILImage.Image | None:
    """Returns a copy of `img` with `message` hidden in one channel, or None if it won't fit."""
    rgb_image = img.convert("RGB")
    payload = message.encode("utf-8")
    if len(payload) > max_message_bytes(rgb_image.width, rgb_image.height):
        return None

    packet = MAGIC + len(payload).to_bytes(4, "big") + payload
    raw = bytearray(rgb_image.tobytes())
    offset = channel_offset(channel)
    for bit_number, bit in enumerate(bytes_to_bits(packet)):
        position = 3 * bit_number + offset
        raw[position] = (raw[position] & 0xFE) | bit  # Replace only the last bit
    return PILImage.frombytes("RGB", rgb_image.size, bytes(raw))


def extract_message(img: PILImage.Image, channel: str) -> str | None:
    """Returns the message hidden in one channel of `img`, or None if there isn't one."""
    rgb_image = img.convert("RGB")
    channel_values = rgb_image.tobytes()[channel_offset(channel)::3]
    header_bits = HEADER_BYTES * 8
    if len(channel_values) < header_bits:
        return None

    header = bits_to_bytes([value & 1 for value in channel_values[:header_bits]])
    if header[:4] != MAGIC:
        return None
    length = int.from_bytes(header[4:], "big")
    if length > max_message_bytes(rgb_image.width, rgb_image.height):
        return None

    end = header_bits + length * 8
    payload_bits = [value & 1 for value in channel_values[header_bits:end]]
    return bits_to_bytes(payload_bits).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Image <-> text helpers (so images can be stored in the State and shown on pages)
# ---------------------------------------------------------------------------
def open_image_bytes(data: bytes | None) -> PILImage.Image | None:
    """Turns uploaded file bytes into an RGB image, or None if they are not an image."""
    if not data:
        return None
    try:
        return PILImage.open(io.BytesIO(data)).convert("RGB")
    except (OSError, TypeError, ValueError):  # Not an image, or not even bytes
        return None


def image_to_base64(img: PILImage.Image) -> str:
    """Returns the image, saved as a lossless PNG, as base64 text."""
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def make_preview(img: PILImage.Image) -> str:
    """Returns a small copy of the image as a data URL that a web page can display."""
    small = img.copy()
    small.thumbnail((PREVIEW_SIZE, PREVIEW_SIZE))
    return DATA_URL_START + image_to_base64(small)


# ---------------------------------------------------------------------------
# Page-building helpers (Drafter lets strings contain HTML, used here for styling)
# ---------------------------------------------------------------------------
def nav_bar() -> list:
    """Returns the navigation buttons shown at the top of every page."""
    return [
        Button("Home", "index"),
        Button("Encode", "encode_form"),
        Button("Decode", "decode_form"),
        Button("About", "about_page"),
        HorizontalRule(),
    ]


def error_banner(state: State) -> list:
    """Returns the red error box, or an empty list when there is no error."""
    if state.error_alert != "":
        return [
            RawHTML(
            '<div style="background:#fdecea;border:1px solid #f5a8a3;color:#8a1f17;'
            'padding:10px 14px;border-radius:6px;margin:8px 0">'
            f"⚠️ <b>Error:</b> {html.escape(state.error_alert)}</div>",
            )
        ]
    return []


def message_html(text: str) -> str:
    """Returns `text` made safe for a web page, keeping its line breaks."""
    return html.escape(text).replace("\n", "<br>")


def stat_card_html(label: str, value: int) -> str:
    """Returns HTML for one statistic box on the home page."""
    return ('<div style="border:1px solid #ccd;border-radius:8px;padding:10px 18px;'
            'text-align:center;min-width:130px">'
            f'<div style="font-size:28px;font-weight:bold">{value}</div>'
            f"<div>{label}</div></div>")


def stats_html(characters: int, encoded: int, decoded: int) -> str:
    """Returns HTML for the row of statistic boxes on the home page."""
    return ('<div style="display:flex;gap:16px;flex-wrap:wrap;margin:10px 0">'
            + stat_card_html("Characters processed", characters)
            + stat_card_html("Messages hidden", encoded)
            + stat_card_html("Messages revealed", decoded)
            + "</div>")


def image_card_html(label: str, source: str) -> str:
    """Returns HTML for one captioned image."""
    return (f'<div style="text-align:center"><div><b>{label}</b></div>'
            f'<img src="{source}" style="max-width:100%;border:1px solid #ccc;'
            'border-radius:6px"></div>')


def image_pair_html(original: str, modified: str) -> str:
    """Returns HTML showing the original and modified images side by side."""
    return ('<div style="display:flex;gap:24px;flex-wrap:wrap;justify-content:center">'
            + image_card_html("Original", original)
            + image_card_html("Modified", modified)
            + "</div>")


def download_link_html(encoded_data: str) -> str:
    """Returns an HTML link that downloads the encoded PNG straight from the page."""
    return (f'<a href="{DATA_URL_START}{encoded_data}" download="hidden_message.png" '
            'style="display:inline-block;padding:8px 16px;background:#2d6cdf;color:white;'
            'border-radius:6px;text-decoration:none;font-weight:bold">'
            "⬇ Download modified image (PNG)</a>")


def secret_box_html(message: str) -> str:
    """Returns HTML for the box that shows a revealed secret message."""
    return ('<div style="border-left:5px solid #2e9e5b;background:#f1faf4;'
            f'padding:12px 16px;border-radius:4px;margin:8px 0">{message_html(message)}</div>')


def count_actions(history: list[StegoRecord], action: str) -> int:
    """Returns how many history records have the given action."""
    total = 0
    for record in history:
        if record.action == action:
            total += 1
    return total


def total_characters(history: list[StegoRecord]) -> int:
    """Returns the total number of message characters across every history record."""
    total = 0
    for record in history:
        total += record.message_length
    return total


def history_rows(history: list[StegoRecord]) -> list[list[str]]:
    """Returns the history as table rows of text, starting with a header row."""
    rows = [["Action", "Image", "Characters", "Channel"]]
    for record in history:
        rows.append([record.action, record.image_size, str(record.message_length),
                     record.channel_used])
    return rows


def check_encode_inputs(source: PILImage.Image | None, message: str) -> str:
    """Returns an error message for bad encode form input, or "" if it looks fine."""
    if source is None:
        return "Please choose a valid image file (PNG or JPG)."
    if source.width * source.height > MAX_PIXELS:
        return "That image is too large. Please use one under about 1400 by 1400 pixels."
    if message == "":
        return "Please type a message to hide."
    return ""


# ---------------------------------------------------------------------------
# Routes: the pages
# ---------------------------------------------------------------------------
@route
def index(state: State) -> Page:
    """Home page: shows summary statistics and the activity history."""
    content: list = [Header("LSB Image Steganographer", 1)]
    content.extend(nav_bar())
    content.extend([
        "Hide a secret message inside an image, then reveal it again. "
        "The hidden message is invisible to the human eye.",
        RawHTML(stats_html(
            total_characters(state.history),
            count_actions(state.history, "Encoded"),
            count_actions(state.history, "Decoded")
        )),
    ])

    if len(state.history) > 0:
        content.extend([Header("Activity history", 2), Table(history_rows(state.history)),
                        LineBreak(), Button("Clear History", "handle_clear_history")])
    else:
        content.append("No activity yet. Start by encoding a message!")
    return Page(state, content)


@route
def encode_form(state: State) -> Page:
    """Encode page: a form for the image upload, the secret message, and the channel."""
    content: list = [Header("Hide a message", 1)]
    content.extend(nav_bar())
    content.extend(error_banner(state))
    content.extend([
        "<b>1. Choose an image</b> (PNG or JPG):",
        LineBreak(),
        FileUpload("uploaded_image", "image/*"),
        LineBreak(),
        LineBreak(),
        "<b>2. Type your secret message:</b>",
        LineBreak(),
        TextArea("secret_text", state.draft_message),
        LineBreak(),
        LineBreak(),
        "<b>3. Pick the color channel to hide it in:</b>",
        LineBreak(),
        SelectBox("channel", list(CHANNELS), state.last_channel),
        LineBreak(),
        LineBreak(),
        Button("Hide Message", "handle_encode"),
    ])
    return Page(state, content)


@route
def decode_form(state: State) -> Page:
    """Decode page: a form for the image upload and the channel to read."""
    content: list = [Header("Reveal a message", 1)]
    content.extend(nav_bar())
    content.extend(error_banner(state))
    content.extend([
        "<b>1. Choose the image with the hidden message</b> (it must be the PNG file "
        "that this site created):",
        LineBreak(),
        FileUpload("uploaded_image", "image/*"),
        LineBreak(),
        LineBreak(),
        "<b>2. Pick the color channel it was hidden in:</b>",
        LineBreak(),
        SelectBox("channel", list(CHANNELS), state.last_channel),
        LineBreak(),
        LineBreak(),
        Button("Reveal Message", "handle_decode"),
    ])
    return Page(state, content)


@route
def result_page(state: State) -> Page:
    """Result page: shows the before/after images after encoding, or the decoded message."""
    content: list = [Header("Result", 1)]
    content.extend(nav_bar())

    if state.last_action == "Encoded":
        content.extend([
            Header("Your message is hidden!", 2),
            RawHTML(
                f"It is stored in the <b>{html.escape(state.last_channel)}</b> channel. "
                "The two images look identical because only the last bit of each color "
                "value changed."
            ),
            
            LineBreak(),
            LineBreak(),
            
            RawHTML(image_pair_html(
                state.source_preview,
                state.encoded_preview
            )),
            
            LineBreak(),
            
            Download(
                "⬇ Download modified image (PNG)",
                "hidden_message.png",
                base64.b64decode(state.encoded_data),
                content_type="image/png"
            ),
            
            LineBreak(),
            LineBreak(),
            
            "Keep the downloaded file as a PNG. JPEG compression or resizing "
            "destroys the hidden message.",
            
            LineBreak(),
            LineBreak(),
            
            Button("Decode This Image Now", "handle_quick_decode"),
            Button("Hide Another Message", "encode_form"),
        ])
    elif state.last_action == "Decoded":
        content.extend([
            Header("Hidden message found!", 2),

            RawHTML(
                f"Found in the <b>{html.escape(state.last_channel)}</b> "
                "channel of this image:"
            ),

            LineBreak(),

            RawHTML(
                f'<img src="{state.source_preview}" '
                'style="max-width:100%;border-radius:6px">'
            ),

            Header("Secret message", 3),

            RawHTML(secret_box_html(state.extracted_message)),

            LineBreak(),

            Button("Decode Another Image", "decode_form")
        ])
    else:
        content.append("Nothing to show yet. Encode or decode an image first.")
    return Page(state, content)


@route
def about_page(state: State) -> Page:
    """About page: explains LSB steganography and how to use the site."""
    content: list = [Header("About LSB Steganography", 1)]
    content.extend(nav_bar())
    content.extend([
        Header("What is it?", 2),
        "Steganography hides a message so nobody even knows it exists. Every pixel of an "
        "image is made of red, green, and blue values from 0 to 255. Changing a value by 1 "
        "(for example 254 to 255) changes the brightness by about 0.4%, which no human eye "
        "can notice. This tool stores one message bit in the last bit of one color "
        "channel of each pixel.",
        Header("How to use it", 2),
        NumberedList([
            "On the Encode page, upload an image, type your message, and pick a channel.",
            "Download the modified PNG from the result page.",
            "Keep it as a PNG: JPEG compression and resizing destroy the hidden bits.",
            "On the Decode page, upload that PNG and pick the SAME channel to read it.",
        ]),
        Header("Limits", 2),
        "An image holds about one byte of message for every 8 pixels. A 1000 by 1000 "
        "pixel image can hide roughly 125,000 bytes. This hides a message but does not "
        "encrypt it, so anyone who knows to look can read it.",
    ])
    return Page(state, content)


# ---------------------------------------------------------------------------
# Routes: the handlers that change the state
# ---------------------------------------------------------------------------
@route
def handle_encode(state: State, uploaded_image: bytes, secret_text: str, channel: str) -> Page:
    """Hides the message in the uploaded image and records it in the history."""
    state.draft_message = secret_text
    state.last_channel = channel

    source = open_image_bytes(uploaded_image)
    state.error_alert = check_encode_inputs(source, secret_text)
    if source is None or state.error_alert != "":
        return encode_form(state)

    encoded = embed_message(source, secret_text, channel)
    if encoded is None:
        capacity = max_message_bytes(source.width, source.height)
        state.error_alert = (f"That message is too long. This image can hold "
                             f"{capacity} bytes.")
        return encode_form(state)

    state.source_preview = make_preview(source)
    state.encoded_preview = make_preview(encoded)
    state.encoded_data = image_to_base64(encoded)
    state.extracted_message = ""
    state.draft_message = ""
    state.last_action = "Encoded"
    state.history.append(StegoRecord(f"{source.width}x{source.height} pixels", "Encoded",
                                     len(secret_text), channel))
    return result_page(state)


@route
def handle_decode(state: State, uploaded_image: bytes, channel: str) -> Page:
    """Reads a hidden message from the uploaded image and records it in the history."""
    state.last_channel = channel
    source = open_image_bytes(uploaded_image)
    if source is None:
        state.error_alert = "Please choose a valid image file (PNG or JPG)."
        return decode_form(state)

    message = extract_message(source, channel)
    if message is None:
        state.error_alert = (f"No hidden message found in the {channel} channel. "
                             "Try a different channel.")
        return decode_form(state)

    state.error_alert = ""
    state.source_preview = make_preview(source)
    state.extracted_message = message
    state.last_action = "Decoded"
    state.history.append(StegoRecord(f"{source.width}x{source.height} pixels", "Decoded",
                                     len(message), channel))
    return result_page(state)


@route
def handle_quick_decode(state: State) -> Page:
    """Decodes the newest encoded image with the channel that was just used."""
    if state.encoded_data == "":
        state.error_alert = "Hide a message first, or upload an image to decode."
        return decode_form(state)
    return handle_decode(state, base64.b64decode(state.encoded_data), state.last_channel)


@route
def handle_clear_history(state: State) -> Page:
    """Empties the activity history and returns to the home page."""
    state.history = []
    return index(state)


# ---------------------------------------------------------------------------
# Unit tests (they run each time the program starts, before the server does)
# ---------------------------------------------------------------------------
def sample_image(width: int, height: int) -> PILImage.Image:
    """Returns a plain test image whose red, green, and blue values are all even."""
    return PILImage.new("RGB", (width, height), (200, 100, 50))


def sample_png_bytes(width: int, height: int) -> bytes:
    """Returns a test image as the bytes of a PNG file, like an upload would be."""
    buffer = io.BytesIO()
    sample_image(width, height).save(buffer, format="PNG")
    return buffer.getvalue()


def round_trip(message: str, channel: str, read_channel: str) -> str | None:
    """Hides `message` in `channel` of a test image, then reads `read_channel`."""
    encoded = embed_message(sample_image(40, 40), message, channel)
    if encoded is None:
        return None
    return extract_message(encoded, read_channel)


def largest_pixel_change(message: str, channel: str) -> int:
    """Returns the biggest change to any color value caused by hiding `message`."""
    original = sample_image(40, 40)
    encoded = embed_message(original, message, channel)
    if encoded is None:
        return -1
    differences = [abs(a - b) for a, b in zip(original.tobytes(), encoded.tobytes())]
    return max(differences)


def state_with_history() -> State:
    """Returns a State holding two history records, for testing."""
    state = new_state()
    state.history = [StegoRecord("10x10 pixels", "Encoded", 10, "Red"),
                     StegoRecord("20x20 pixels", "Decoded", 5, "Blue")]
    return state


def state_with_error(message: str) -> State:
    """Returns a State whose error_alert is `message`, for testing."""
    state = new_state()
    state.error_alert = message
    return state


def encoded_state(message: str, channel: str) -> State:
    """Returns the State after the encode route hides `message` in a test image."""
    return handle_encode(new_state(), sample_png_bytes(40, 40), message, channel).state


# Bit conversion helpers (bytes are converted to lists of numbers before comparing,
# because bakery's assert_equal cannot compare bytes values)
assert_equal(bytes_to_bits(b"A"), [0, 1, 0, 0, 0, 0, 0, 1])
assert_equal(list(bits_to_bytes([0, 1, 0, 0, 0, 0, 0, 1])), [65])  # 65 is "A"
assert_equal(list(bits_to_bytes([])), [])
assert_equal(list(bits_to_bytes([1, 1, 1])), [])  # Fewer than 8 bits make no byte
assert_equal(list(bits_to_bytes(bytes_to_bits(b"Hi!"))), [72, 105, 33])

# channel_offset and max_message_bytes
assert_equal(channel_offset("Red"), 0)
assert_equal(channel_offset("Green"), 1)
assert_equal(channel_offset("Blue"), 2)
assert_equal(max_message_bytes(40, 40), 192)
assert_equal(max_message_bytes(2, 2), 0)

# embed_message / extract_message
assert_equal(round_trip("Hello", "Red", "Red"), "Hello")
assert_equal(round_trip("Hello", "Green", "Green"), "Hello")
assert_equal(round_trip("Hello", "Blue", "Blue"), "Hello")
assert_equal(round_trip("", "Blue", "Blue"), "")
assert_equal(round_trip("héllo ✓ 你好", "Blue", "Blue"), "héllo ✓ 你好")
assert_equal(round_trip("a" * 192, "Blue", "Blue"), "a" * 192)  # Exactly full
assert_equal(round_trip("a" * 193, "Blue", "Blue"), None)       # One byte too many
assert_equal(round_trip("Hello", "Blue", "Red"), None)          # Wrong channel
assert_equal(extract_message(sample_image(40, 40), "Blue"), None)  # Nothing hidden
assert_equal(extract_message(sample_image(4, 4), "Blue"), None)    # Image too small
assert_equal(largest_pixel_change("Hello", "Green"), 1)

# Image <-> text helpers
assert_equal(open_image_bytes(None), None)
assert_equal(open_image_bytes(b""), None)
assert_equal(open_image_bytes(b"this is not an image"), None)
assert_equal(open_image_bytes(sample_png_bytes(5, 7)).size, (5, 7))
assert_equal(make_preview(sample_image(10, 10)).startswith(DATA_URL_START), True)
assert_equal(image_to_base64(sample_image(2, 2)).startswith("iVBOR"), True)  # PNG signature

# Page helpers
assert_equal(message_html("a<b>\nc"), "a&lt;b&gt;<br>c")
assert_equal("Original" in image_pair_html("x", "y"), True)
assert_equal('download="hidden_message.png"' in download_link_html("abc"), True)
assert_equal("42" in stat_card_html("Things", 42), True)
assert_equal("Messages hidden" in stats_html(1, 2, 3), True)
assert_equal("a&lt;b" in secret_box_html("a<b"), True)
assert_equal(count_actions(state_with_history().history, "Encoded"), 1)
assert_equal(count_actions([], "Encoded"), 0)
assert_equal(total_characters([]), 0)
assert_equal(total_characters(state_with_history().history), 15)
assert_equal(history_rows([]), [["Action", "Image", "Characters", "Channel"]])
assert_equal(history_rows(state_with_history().history)[1],
             ["Encoded", "10x10 pixels", "10", "Red"])
assert_equal(check_encode_inputs(None, "hi"), "Please choose a valid image file (PNG or JPG).")
assert_equal(check_encode_inputs(sample_image(5, 5), ""), "Please type a message to hide.")
assert_equal(check_encode_inputs(sample_image(5, 5), "hi"), "")
assert_equal(check_encode_inputs(sample_image(2001, 2001), "hi"),
             "That image is too large. Please use one under about 1400 by 1400 pixels.")
assert_equal(len(error_banner(new_state())), 0)
assert_equal(len(error_banner(state_with_error("Oops"))), 1)
assert_equal(len(nav_bar()), 5)

# Routes that display pages
assert_equal(len(index(state_with_history()).state.history), 2)
assert_equal(index(new_state()).state.error_alert, "")
assert_equal(encode_form(state_with_error("Oops")).state.error_alert, "Oops")
assert_equal(decode_form(new_state()).state.last_channel, "Blue")
assert_equal(result_page(new_state()).state.last_action, "")
assert_equal(result_page(encoded_state("Hi", "Red")).state.last_action, "Encoded")
assert_equal(about_page(new_state()).state.history, [])

# Routes that change the state
assert_equal(handle_clear_history(state_with_history()).state.history, [])
assert_equal(handle_encode(new_state(), b"", "hi", "Blue").state.error_alert,
             "Please choose a valid image file (PNG or JPG).")
assert_equal(handle_encode(new_state(), sample_png_bytes(5, 5), "", "Red").state.error_alert,
             "Please type a message to hide.")
assert_equal(handle_encode(new_state(), sample_png_bytes(5, 5), "hi", "Red").state.error_alert,
             "That message is too long. This image can hold 0 bytes.")
assert_equal(handle_encode(new_state(), b"", "keep me", "Red").state.draft_message, "keep me")
assert_equal(handle_encode(new_state(), b"", "hi", "Red").state.last_channel, "Red")
assert_equal(encoded_state("Hello", "Green").last_action, "Encoded")
assert_equal(encoded_state("Hello", "Green").error_alert, "")
assert_equal(encoded_state("Hello", "Green").draft_message, "")
assert_equal(encoded_state("Hello", "Green").history,
             [StegoRecord("40x40 pixels", "Encoded", 5, "Green")])
assert_equal(encoded_state("Hello", "Green").encoded_data != "", True)
assert_equal(handle_decode(new_state(), b"", "Blue").state.error_alert,
             "Please choose a valid image file (PNG or JPG).")
assert_equal(handle_decode(new_state(), sample_png_bytes(40, 40), "Green").state.error_alert,
             "No hidden message found in the Green channel. Try a different channel.")
assert_equal(handle_quick_decode(new_state()).state.error_alert,
             "Hide a message first, or upload an image to decode.")
assert_equal(handle_quick_decode(encoded_state("Secret!", "Red")).state.extracted_message,
             "Secret!")
assert_equal(handle_quick_decode(encoded_state("Secret!", "Red")).state.last_action, "Decoded")
assert_equal(len(handle_quick_decode(encoded_state("Secret!", "Red")).state.history), 2)


# ---------------------------------------------------------------------------
# Start the website
# ---------------------------------------------------------------------------
start_server(new_state())


