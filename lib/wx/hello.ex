defmodule Wx.Hello do

  import Bitwise

  # Similar to our first in wx_hello.erl
  def say_hello() do
    :wx.new()
    m = :wxMessageDialog.new(:wx.null(), "Hello World")
    :wxMessageDialog.showModal(m)
    :wxMessageDialog.destroy(m)
  end

  def say_hello_with_style() do
    :wx.new()
    style =
      :wx_const.wxICON_QUESTION()
      |> bor(:wx_const.wxYES_NO())
      |> bor(:wx_const.wxYES_DEFAULT())

    m = :wxMessageDialog.new(:wx.null(), "Hello!?", [{:style, style}])

    :wxMessageDialog.showModal(m)
    :wxMessageDialog.destroy(m)
  end
end
