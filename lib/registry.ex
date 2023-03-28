defmodule Misc.Counter.Registry do

  use GenServer

  def start_link(account_id) do
    name = via_tuple(account_id)
    GenServer.start_link(__MODULE__, [], name: name)
  end

  defp via_tuple(account_id) do
    {:via, Registry, {:account_process_registry, account_id}}
  end

  def order_placed(account_id) do
    GenServer.call(via_tuple(account_id), :order_placed)
  end  # genserver callbacks not shown for simplicityend
end
