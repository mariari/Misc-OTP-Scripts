defmodule MiscTest.Narwhal do

  use ExUnit.Case, async: true

  import Misc.Narwhal.Validator
  import Misc.Narwhal.Primary

  doctest Misc

  test "Signing works on round 0" do
    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)

    {pub, priv} = :crypto.generate_key(:rsa, {1024,65537})

    block = %{block: %{transactions: [], certificates: []}, round: 0, pub_key: pub}

    _signed = create_signature(block, priv)

    signed_block = {block, create_signature(block, priv)}

    assert sign_block(p_pid, signed_block) != :error


  end

  test "State transition happens as we expect" do


    {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

    p_pid = Misc.Narwhal.Validator.get_primary(pid)


    # this will have to change when we actually validate
    assert new_certificate(p_pid, 5) == :ack
    assert new_certificate(p_pid, 5) == :ack

    assert is_tuple(new_certificate(p_pid, 5)) # trigger mode change

    assert is_bitstring (new_certificate(p_pid, 5)) # should not understand

  end



end
