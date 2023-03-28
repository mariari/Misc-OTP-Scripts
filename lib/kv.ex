##################################################
#             Joe Armstrong's Thesis             #
#                  Chapter 6                     #
##################################################

defmodule Misc.KV do

  use GenServer

  def start() do
    # {:name, thing} gives it the name locally
    GenServer.start_link(__MODULE__, :arg1, name: __MODULE__)
  end

  def stop() do
    GenServer.cast(__MODULE__, :stop)
  end

  def init(_arg1) do
    :io.format("Key-Value server starting ~n")
    {:ok, Map.new}
  end

  # client routine
  def store(key, val) do
    GenServer.call(__MODULE__, {:store, key, val})
  end

  # client routine
  def lookup(key) do
    GenServer.call(__MODULE__, {:lookup, key})
  end

  # Remote Procedure Calls (RPC)
  # this is the server side
  def handle_call({:store, key, val}, _from, dict) do
    {:reply, :ack, Map.put(dict, key, val)}
  end

  def handle_call({:lookup, :crash}, _from, dict) do
    _ = 1/0
    {:reply, :ack, dict}
  end

  def handle_call({:lookup, key}, _from, dict) do
    {:reply, Map.fetch(dict, key), dict}
  end

  def handle_cast(:stop, dict), do: {:stop, :normal, dict}

  def terminate(_reason, _dict) do
    :io.format("K-V server is terminating ~n")
  end
end
