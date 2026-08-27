-- Prepare the Markdown conformance specification for the LaTeX edition.
--
-- The Markdown file carries repository-facing title and status paragraphs. The
-- LaTeX title page owns that material, so this filter starts at the Abstract,
-- converts it to an abstract environment, shifts the remaining headings up one
-- level, and removes the hand-written section numbers before LaTeX numbers them.

local function heading_text(header)
  return pandoc.utils.stringify(header.content)
end

local function heading_inlines(text)
  local parsed = pandoc.read(text, "markdown")
  if #parsed.blocks == 1 and parsed.blocks[1].t == "Para" then
    return parsed.blocks[1].content
  end
  return { pandoc.Str(text) }
end

local function set_table_widths(block)
  local count = #block.colspecs
  local widths = nil
  local contents = pandoc.utils.stringify(block)

  if count == 2 then
    if contents:find("Parameter", 1, true)
        and contents:find("Initial value", 1, true) then
      widths = { 0.46, 0.54 }
    else
      widths = { 0.30, 0.70 }
    end
  elseif count == 3 then
    widths = { 0.22, 0.39, 0.39 }
  end

  if widths then
    for index, width in ipairs(widths) do
      block.colspecs[index][2] = width
    end
  end

  return block
end

local function verbatim_delimiter(text)
  for _, delimiter in ipairs({ "|", "!", "+", ";", ":", "@" }) do
    if not text:find(delimiter, 1, true) then
      return delimiter
    end
  end
  error("inline code contains every supported LaTeX delimiter")
end

function Code(code)
  if not FORMAT:match("latex") then
    return nil
  end

  local delimiter = verbatim_delimiter(code.text)
  return pandoc.RawInline(
    "latex",
    "\\path" .. delimiter .. code.text .. delimiter
  )
end

function CodeBlock(code)
  if not FORMAT:match("latex") then
    return nil
  end

  return pandoc.RawBlock(
    "latex",
    "\\begin{UMICodeBlock}\n" .. code.text .. "\n\\end{UMICodeBlock}"
  )
end

function Pandoc(document)
  local output = {}
  local started = false
  local abstract_open = false

  for _, block in ipairs(document.blocks) do
    if block.t == "Header" and heading_text(block) == "Abstract" then
      started = true
      abstract_open = true
      table.insert(output, pandoc.RawBlock("latex", "\\begin{abstract}"))
    elseif started then
      if block.t == "Header" then
        if abstract_open then
          table.insert(output, pandoc.RawBlock("latex", "\\end{abstract}"))
          abstract_open = false
        end

        block.level = math.max(1, block.level - 1)
        local title = heading_text(block):gsub("^%d+%.?%d*%.?%s+", "")
        block.content = heading_inlines(title)
      elseif block.t == "Table" then
        block = set_table_widths(block)
      end
      table.insert(output, block)
    end
  end

  if abstract_open then
    table.insert(output, pandoc.RawBlock("latex", "\\end{abstract}"))
  end

  document.blocks = output
  return document
end
