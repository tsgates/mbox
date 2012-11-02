void toto()
{
    char buffer[4096];
    buffer[0] = 0;
    toto();
}

int main()
{
    toto();
    return 0;
}
