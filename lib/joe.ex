# This follows Joe Armstrong's thesis

# Chapter 3

defmodule Math do
  def areas(xs) do
    xs |> Stream.map(&area/1) |> Enum.sum
  end

  defp area({:square,x}) do
    x * x
  end

  defp area({:rectangle, x, y}) do
    x * y
  end
end

# Chapter 4

defmodule Server1 do

  @doc """
  Starts a server

  ### parameters
  - name - the name of the server
  - f - is the function which characterizes the behavior of the server
  - state - is the initial state
  """
  def start(name, f, state) do
    Process.spawn(fn -> loop(name, f, state) end, [])
    |> Process.register(name)
  end

  @doc """
  stops the server

  ### parameters
  - name - the name of the server to stop
  """
  def stop(name) do
    send(name, :stop)
  end

  @doc """
  performs a remote procedure call on the server

  ### parameters
  - name - the name of the server
  - query - the query for the server function to run on.
  """
  def rpc(name, query) do
    send(name, {self(), query})
    receive do
      {_name, reply} -> reply
    end
  end

  defp loop(name, f, state) do
    receive do
      :stop -> nil
      {pid, query} ->
        {reply, state1} = f.(query, state)
        send(pid, {name, reply})
        loop(name, f, state1)
    end
  end
end

# Very simple Home Location Register (HLR)

defmodule Vshlr1 do
  @moduledoc """
  I implement a very simple Home Location Register (HLR), or VSHLR for short.

  ### examples

      iex(122)> Vshlr1.start()
      true
      iex(123)> Vshlr1.find("joe")
      :error
      iex(124)> Vshlr1.i_am_at("joe", "sics")
      :ok
      iex(125)> Vshlr1.find("joe")
      {:ok, "sics"}
  """

  import Server1, only: [start: 3, stop: 1, rpc: 2]

  @doc """
  start the HLR
  """
  def start() do
    start(:vshlr, &handle_event/2, Map.new())
  end


  @doc """
  stop the HLR
  """
  def stop() do
    stop(:vshlr)
  end

  @doc """
  tlles the HLR that Person is at the location

  ###parameters
  - person - the person
  - loc - the location
  """
  def i_am_at(who, where) do
    rpc(:vshlr, {:i_am_at, who, where})
  end

  @doc """
  Tries to find the position of the person in the HLR. Responds with
  {:ok, loc} where loc is the last reported location or error if it
  doesn't know where the person is

  ###parameters
  - person - the person
  """
  @spec find(any()) :: {:ok, any()} | none()
  def find(person) do
    rpc(:vshlr, {:find, person})
  end

  def handle_event({:i_am_at, who, where}, dict) do
    {:ok, Map.put(dict, who, where)}
  end

  def handle_event({:find, who}, dict) do
    {Map.fetch(dict, who), dict}
  end

end

# really server 3, but since 3 and 2 are so close, we keep them as 1
defmodule Server2 do

  @doc """
  Starts a server

  ### parameters
  - name - the name of the server
  - f - is the function which characterizes the behavior of the server
  - state - is the initial state
  """
  def start(name, f, state) do
    Process.spawn(fn -> loop(name, f, state) end, [])
    |> Process.register(name)
  end

  @doc """
  stops the server

  ### parameters
  - name - the name of the server to stop
  """
  def stop(name) do
    send(name, :stop)
  end

  @doc """
  Swaps the running code with a new version
  """
  def swap_code(name, f) do
    rpc(name, {:swap_code, f})
  end

  @doc """
  performs a remote procedure call on the server. Properly handle
  errors when they do occur

  ### parameters
  - name - the name of the server
  - query - the query for the server function to run on.
  """
  def rpc(name, query) do
    send(name, {self(), query})
    receive do
      {_name, :crash}     -> exit(:rpc)
      {_name, :ok, reply} -> reply
    # in reality a supervisor tree should be had
    after 10000 -> exit(:timeout)
    end
  end

  defp loop(name, f, state) do
    receive do
      :stop -> nil
      {pid, {:swap_code, f1}} ->
        send(pid, {name, :ok, :ack})
        loop(name, f1, state)
      {pid, query} ->
        try do
          {reply, state1} = f.(query, state)
          send(pid, {name, :ok, reply})
          loop(name, f, state1)
        catch
          _, why ->
            log_error(name, query, why)
            send(pid, {name, :crash})
            loop(name, f, state)
        end
    end
  end

  defp log_error(name, query, why) do
    :io.format("Server ~p query ~p caused exception ~p~n", [name, query, why])
  end
end

defmodule Vshlr2 do
  @moduledoc """
  I implement a very simple Home Location Register (HLR), or VSHLR for short.

  ### examples

      iex(122)> Vshlr2.start()
      true
      iex(123)> Vshlr2.find("joe")
      :error
      iex(124)> Vshlr2.i_am_at("joe", "sics")
      Server vshlr query {i_am_at,<<"joe">>,<<"sics">>} ca
      iex(125)> Server2.swap_code(:vshlr2, &Vshlr1.handle_event/2)
      :ack
      iex(126)> Vshlr2.i_am_at("joe", "sics")
      :ok
  """

  import Server2, only: [start: 3, stop: 1, rpc: 2]

  def start(), do: start(:vshlr2, &handle_event/2, Map.new())

  def stop(), do: stop(:vshlr2)

  def i_am_at(who, where) do
    rpc(:vshlr2, {:i_am_at, who, where})
  end

  @spec find(any()) :: {:ok, any()} | none()
  def find(person) do
    rpc(:vshlr2, {:find, person})
  end

  def handle_event({:i_am_at, who, where}, dict) do
    _ = 1/0
    {:ok, Map.put(dict, who, where)}
  end

  def handle_event({:find, who}, dict) do
    {Map.fetch(dict, who), dict}
  end

end
