defmodule MiscTest.Counter do

  use ExUnit.Case, async: true
  doctest Misc

  test "Both Reset" do
    resume = Misc.Counter.Global.terminate()

    children = [
      # :fooy also works
      {Misc.Counter, [name: Misc.Counter]},
      # how should we handle this failing
      {Misc.Living, %{mod: Misc.Counter.Global, initial_value: 0, pid: self()}}
      # {Misc.Counter.Global, 0}
    ]

    {_, link} =
      try do
        l = Supervisor.start_link(children, strategy: :one_for_all)
        assert_receive :alive, 20_000
        l
      catch
        :exit, _ ->
          # Counter already in a supervisor, can't do the tests
          {:err, false}
      end

    if link do
      assert Misc.Counter.value(Misc.Counter) == 0

      Misc.Counter.increment(Misc.Counter)

      assert Misc.Counter.value(Misc.Counter) == 1

      # lets crash the child! Terminate and crash are same but less noisy
      terminate_child()

      # The process should be restarted, error if it doesn't
      assert_receive :alive, 20_000

      assert Misc.Counter.value(Misc.Counter) == 0

      # shut down the current link
      Supervisor.stop(link)
    end

    # resume the original counter process
    case resume do
      {:ok, val} -> Misc.Counter.Global.start_link(val)
      _ -> :ok
    end
  end

  def crash_child() do
    # with catch_exit the same behavior happens as if I don't print
    Misc.Counter.Global.increment_by("hi")
    |> catch_error
    |> catch_exit
  end

  def terminate_child() do
    Misc.Counter.Global.terminate()
  end

end
