defmodule Experiment do
  def process(home) do
    0..300
    |> Enum.map(fn i ->
      {:ok, server} = GenServer.start_link(Server, i)
      spawn(fn () -> forever_read(server, 0, home) end)
      spawn(fn () -> forever_write(server, i) end)
    end)
  end

  def forever_read(server, initial, home) do
    if Enum.random(0..5) == 1 do
      send(home, {:read_data, initial})
    end
    new_initial = GenServer.call(server, :read)
    :timer.sleep(100)
    forever_read(server, new_initial, home)
  end

  def forever_write(server, d) do
    GenServer.cast(server, {:write, d})
    :timer.sleep(100)
    forever_write(server, d + 1)
  end

end

defmodule Server do
  use GenServer
  def init(storage) do
    {:ok, storage}
  end

  def handle_call(:read, _from, data) do
    {:reply, data, data}
  end

  def handle_cast({:write, data}, _state) do
    {:noreply, data}
  end
end
