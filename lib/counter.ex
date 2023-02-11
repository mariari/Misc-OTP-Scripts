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
