# Diagram sources

The `.html` files are the editable sources. The matching `.svg` files are
portable exports embedded by the Markdown documents.

After editing an HTML diagram, regenerate its SVG from the Diagram Design
skill directory:

```sh
python3 scripts/export_svg.py \
  /path/to/diagram.html /path/to/diagram.svg \
  --system-fonts
```

The `--system-fonts` export contains no remote font request and is the version
intended for GitHub rendering. Commit the HTML and regenerated SVG together.
