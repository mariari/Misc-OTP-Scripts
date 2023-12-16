defmodule Misc.Macro.Utilities do
 defmacro in_quote(do: expression) do
   quote do
     {:quote, [context: Elixir], [[do: unquote(expression)]]}
   end
 end
end

defmodule Misc.Macro do
  require Misc.Macro.Utilities
  import Misc.Macro.Utilities

  @doc """

  Properly expands macros in a readable manner, the form is
  automatically put in a quote, so no need to quote it coming in

  ## Parameters

  - expression (expression) - the expression one wishes to expand

  ## Returns

  The macro expanded code

  ## Examples

      iex> expand(do: unless 3 do 5 end)
      case 3 do
        x when Kernel.in(x, [false, nil]) -> 5
        _ -> nil
      end
  """


  defmacro expand(do: expression) do
    quote do
      Macro.expand(unquote(in_quote(do: expression)), __ENV__)
      |> Macro.to_string()
      |> IO.puts()
    end
  end

  @doc """

  Properly expands macros once in a readable manner, the form is
  automatically put in a quote, so no need to quote it coming in

  ## Parameters

  - expression (expression) - the expression one wishes to expand

  ## Returns

  The macro expanded code

  ## Examples

      iex> expand_once(do: unless 3 do 5 end)
      if 3 do
        nil
      else
        5
      end
  """
 defmacro expand_once(do: expression) do
    quote do
      Macro.expand_once(unquote(in_quote(do: expression)), __ENV__)
      |> Macro.to_string()
      |> IO.puts()
    end
  end

  defmacro expand_original(do: expression) do
    quote bind_quoted: [expression: {:quote, [context: Elixir], [[do: expression]]}] do
      Macro.expand(expression, __ENV__)
      |> Macro.to_string()
      |> IO.puts()
    end
  end
end
