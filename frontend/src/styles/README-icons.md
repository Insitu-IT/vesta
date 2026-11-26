# Tabler Icons webfont asset

`tabler-icons.min.css` and `fonts/tabler-icons.woff2` are the prebuilt Tabler
Icons 3.35.0 webfont assets, retained under the accompanying
`../../public/licenses/tabler-icons.MIT.txt` (MIT), which Vite copies into the
shipped `dist/` tree. The CSS font-face keeps only WOFF2; the icon
class mappings and glyph bytes are otherwise unchanged from that version.

The application imports these static assets directly. The npm
`@tabler/icons-webfont` package included image-generation tooling (`sharp`) as
a production dependency, although the application never runs that tooling.
Do not reintroduce the package merely to serve the prebuilt font; review its
license, glyph changes and frontend scan when updating these assets.
