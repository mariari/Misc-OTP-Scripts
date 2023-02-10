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

defmodule Misc.Counter.Global do
  use Agent

  def start_link(initial_value) do
    Agent.start_link(fn -> initial_value end, name: __MODULE__)
  end

  def terminate do
    try do
      value = value()
      {Agent.stop(__MODULE__), value}
    catch
      :exit, _ -> {:error, :already_terminated}
    end
  end

  def value do
    Agent.get(__MODULE__, & &1)
  end

  def increment do
    Agent.update(__MODULE__, &(&1 + 1))
  end

  def increment_by(value) do
    Agent.update(__MODULE__, &(&1 + value))
  end
end

# Looks neat in the process viewer
defmodule Misc.Counter do
  use Agent

  def start_link(opts) do
    {initial_value, opts} = Keyword.pop(opts, :initial_value, 0)
    Agent.start_link(fn -> initial_value end, opts)
  end

  def value(agent) do
    Agent.get(agent, & &1)
  end

  def increment(agent) do
    Agent.update(agent, &(&1 + 1))
  end
end

defmodule Misc.Living do
  @moduledoc """
  Ι notify the given pid when I spawn with the message :alive
  """
  def start_link(%{call: {mod, func, val}, pid: pid}) do
    ret = apply(mod, func, val)
    send(pid, :alive)
    ret
  end

  def child_spec(%{mod: mod, initial_value: val, pid: pid}) do
    %{start: func} = mod.child_spec(val)
    %{id: __MODULE__, start: {__MODULE__, :start_link, [%{call: func, pid: pid}]}}
  end

  def child_spec(pod) do
    start_link(Map.put(pod, :initial_value, []))
  end
end
