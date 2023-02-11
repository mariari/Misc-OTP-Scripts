defmodule Misc.First do
  @moduledoc """
  This is the First module for implementing basic programs
  """

  def hello do
    Misc.hello()
  end

  def fact(n), do: fact(n, 1)

  def fact(n, acc) when n > 0 do
    fact(n - 1, acc * n)
  end

  def fact(n, acc) when n <= 0 do
    acc
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
  @spec fact_proper(integer) :: integer
  def fact_proper(n) do
    1..n |> Enum.reduce(1, &*/2)
  end
end
