defmodule Misc.First do
  @moduledoc """
  This is the First module for implementing basic programs
  """

  def hello do
    MiscElixirScripts.hello()
  end

  @doc """
  Computes the factorial of a number

  ## Parameters

  - n (number) - the number

  ## Returns

  the factorial of the input (n!)

  ## Examples

      iex> Misc.First.fact(5)
      120
  """
  def fact(n), do: fact(n, 1)

  def fact(n, acc) when n > 0 do
    fact(n-1, acc * n)
  end

  def fact(n, acc) when n <= 0 do
    acc
  end

end
