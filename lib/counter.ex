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


# this is like the other two, but registers a dns name
defmodule Misc.Counter.Registry do
  @moduledoc """
  We need to start a registry before we can use this

  iex(1)> Registry.start_link(keys: :unique, name: :account_process_registry)
  iex(14)> Misc.Counter.Registry.start_link(20)
  {:ok, #PID<0.703.0>}
  iex(15)> Misc.Counter.Registry.increment(5)
  1
  iex(16)> Misc.Counter.Registry.increment_by(5, 10)
  11

  """
  use GenServer

  def init(x), do: {:ok, x}

  def start_link(id) do
    GenServer.start_link(__MODULE__, 0, name: via(id))
  end

  defp via(account_id) do
    {:via, Registry, {:account_process_registry, account_id}}
  end

  def increment_by(id, value) do
    GenServer.call(via(id), {:increment, value})
  end

  def increment(id) do
    GenServer.call(via(id), {:increment, 1})
  end

  def stop(id) do
    GenServer.cast(via(id), :stop)
  end

  def handle_call({:increment, value}, _from, state) do
    new_state = state + value
    {:reply, new_state, new_state}
  end

  def handle_cast(:stop, dict), do: {:stop, :normal, dict}
end
