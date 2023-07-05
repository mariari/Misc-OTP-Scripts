# Lets see if we can dynamically generate some code

# this quote actually builds up an AST for Code.eval_quoted to fixup, we can work with this.
quote do
  defmodule Misc.First.Evaled do
    def fact(n), do: fact(n, 1)
    def fact(n, acc) when n > 0 do
      fact(n - 1, acc * n)
    end
    def fact(n, acc) when n <= 0 do
      acc
    end
  end
end
|> Code.eval_quoted()
