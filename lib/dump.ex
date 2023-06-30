defmodule Misc.Dump do
  @moduledoc """

  Ι help the BeamFile module api, by providing extra utility
  functions for dumping.

  If you want to view dumps of functions then call
  - `Misc.Dump.byte_fun/2`

  Otherwise just use
  `BeamFile`
  """


  @doc """
  Dumps the bytecode representation of a particular function in a module

  ### Parameters
  - `input` - the input module
  - `function_name` - the name of the function as an atom

  ### Examples

      iex> Misc.Dump.byte_fun(Misc.Narwhal.Primary, :block_creation)

  """
  @spec byte_fun(BeamFile.input(), atom()) :: nil
  def byte_fun(input, function_name) do
    BeamFile.byte_code!(input)
    |> Tuple.to_list
    |> List.last
    |> Enum.filter(fn x -> Enum.at(Tuple.to_list(x), 1) == function_name end)
    |> List.first
    |> IO.inspect(limit: :infinity)
    nil
  end

end
