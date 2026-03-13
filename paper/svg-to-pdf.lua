-- Pandoc Lua filter: rewrite .svg image paths to .pdf for LaTeX/PDF output.
-- SVGs must be pre-converted to PDF via rsvg-convert before running pandoc.
function Image(el)
  if el.src:match("%.svg$") then
    el.src = el.src:gsub("%.svg$", ".pdf")
  end
  return el
end
