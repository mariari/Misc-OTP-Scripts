defmodule MiscTest do
  use ExUnit.Case
  doctest Misc

  test "greets the world" do

    assert Misc.hello() == :world

  end

  test "Factorial check" do
    assert Misc.First.fact(5) == 120
    assert Misc.First.fact(5) == Misc.First.fact_proper(5)
  end

  test "Both Reset" do

    resume = Misc.Counter.Global.terminate()

    children = [
      {Misc.Counter, [name: Misc.Counter]}, # :fooy also works
      # how should we handle this failing
      {Misc.Counter.Global, 0}
    ]

    {_, link} =
      try do
        Supervisor.start_link(children, strategy: :one_for_all)

      catch
        :exit, _ -> {:err, false}
      # Counter already in a supervisor, can't do the tests
      end

    if link do
    Process.flag(:trap_exit, true)
      assert Misc.Counter.value(Misc.Counter) == 0

      Misc.Counter.increment(Misc.Counter)

      assert Misc.Counter.value(Misc.Counter) == 1


      # lets crash the child!
      crash_child()

      assert Misc.Counter.value(Misc.Counter) == 0

      # shut down the current link
      Supervisor.stop(link)
    end

    # resume the original counter process
    case resume do
      {:ok, val} -> Misc.Counter.Global.start_link(val)
      _          -> :ok
    end

  end

  def crash_child() do
    # with catch_exit the same behavior happens as if I don't print
    try do
      Misc.Counter.Global.increment_by("hi")
    catch
      :exit, e ->
        IO.puts("have to have this here...")
        3
    end
  end

  def terminate_child() do


    # making sure we trap exits
    Process.flag(:trap_exit, true)

    Misc.Counter.Global.terminate()

  end

end
