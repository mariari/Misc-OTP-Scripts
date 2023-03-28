defmodule MiscTest.Vshlr do

  use ExUnit.Case, async: true
  doctest Misc

  test "Server 1 works as expected" do
    try do
      Vshlr1.start()
      nil
    rescue
      ArgumentError -> nil
    end
    # can't test before putting it in case the server is already
    # live.... Issues of single use databases

    Vshlr1.i_am_at("joe", "sics")

    assert Vshlr1.find("joe") == {:ok, "sics"}
  end

  test "Server 2 can update as expected" do
    try do
      Vshlr2.start()
      nil
    rescue
      ArgumentError -> Server2.swap_code(:vshlr2, &Vshlr2.handle_event/2)
    end

    try do
      Vshlr2.i_am_at("joe", "sics")
      assert false, "we should crash!"
    catch
      :exit, _value ->
        assert true, "we should have crashed!"
    end

    Server2.swap_code(:vshlr2, &Vshlr1.handle_event/2)
    assert Vshlr2.i_am_at("joe", "sics") == :ok

  end
end

# Exceptions - are when the runtime doesn't know what to do
# Errors - happen when the programmer doesn't know what to do
# lookup example is quite interesting

# lookup replaced by
# Erlang - Elixir
# fetch  - fetch!
# is_key - has_key?
# search - fetch
