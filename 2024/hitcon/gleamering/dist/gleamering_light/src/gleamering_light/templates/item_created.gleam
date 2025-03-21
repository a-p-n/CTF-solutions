// DO NOT EDIT: Code generated by matcha from item_created.matcha

import gleam/string_builder.{type StringBuilder}

import gleamering_hope/item.{type Item}
import gleamering_light/templates/item as item_template

pub fn render_builder(item item: Item, display display: Bool) -> StringBuilder {
  let builder = string_builder.from_string("")
  let builder =
    string_builder.append(
      builder,
      "
",
    )
  let builder =
    string_builder.append(
      builder,
      "
<input
  autofocus 
  required 
  maxlength=\"500\"
  class=\"new-post\"
  placeholder=\"What needs to be complete?\"
  name=\"content\"
  autocomplete=\"off\"
>

",
    )
  let builder = case display {
    True -> {
      let builder =
        string_builder.append(
          builder,
          "
<div hx-swap-oob=\"beforeend\" id=\"post-list\">
  ",
        )
      let builder =
        string_builder.append_builder(
          builder,
          item_template.render_builder(item, False),
        )
      let builder =
        string_builder.append(
          builder,
          "
</div>
",
        )

      builder
    }
    False -> {
      builder
    }
  }
  let builder =
    string_builder.append(
      builder,
      "
",
    )

  builder
}

pub fn render(item item: Item, display display: Bool) -> String {
  string_builder.to_string(render_builder(item: item, display: display))
}
